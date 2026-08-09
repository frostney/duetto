program wsinterop;

// Live-socket battery: duetto TWSClient against duetto TWSServer over real
// TCP (loopback), plus a raw-socket section that injects protocol
// violations a conforming client cannot produce and asserts the close
// codes RFC 6455 (and Autobahn cases 4.x/7.x) require, a plain-request
// section covering the single-port OnPlainRequest fallback, and a
// concurrent-connections stress section — 33 client threads (28 echo,
// 4 abrupt-drop, 1 pusher) of echo/burst/clean-close cycles racing
// abrupt raw-socket drops and server-initiated pushes, ended by a
// Shutdown with connections still open.
//
// On Linux there is also a wss:// section (duetto#22): a second server
// with server TLS terminated by the epoll transport itself, driven from
// a runtime-generated CA + leaf identity. It is Linux-only on purpose —
// the epoll transport is the thing under test, and the macOS client
// rides SecureTransport, which cannot be handed a throwaway CA without
// keychain surgery. It skips with a clear line when the openssl CLI is
// not installed, so a local macOS/Windows run stays green.
//
// Exit 0 = every check passed.

{$I Shared.inc}

uses
  {$ifdef UNIX} cthreads, BaseUnix, {$endif}
  syncobjs,
  SysUtils, Classes, Sockets,
  TransportSecurity,
  WS.Client, WS.Frame, WS.Handshake, WS.Server, WS.Transport;

{$ifdef WINDOWS}
// Declared here rather than pulling the whole Windows unit into a file
// that already speaks Sockets: the watchdog needs exactly one symbol.
procedure ExitProcess(AExitCode: UInt32); stdcall;
  external 'kernel32' name 'ExitProcess';
{$endif}

type
  {$ifdef UNIX}
  TInteropTimeVal = record
    Seconds: PtrInt;
    Microseconds: PtrInt;
  end;
  {$endif}

  // struct linger: int pair on Unix, u_short pair on WinSock.
  TInteropLinger = record
    {$ifdef WINDOWS}
    OnOff: Word;
    Seconds: Word;
    {$else}
    OnOff: LongInt;
    Seconds: LongInt;
    {$endif}
  end;

  TEcho = class
    procedure OnMsg(AConn: TWSConnection; AText: Boolean; P: PByte; Len: NativeInt);
  end;

  // Single-port fallback host for the plain-request section. Answers with
  // a body derived from the request line, so the client can assert the
  // exact bytes the server put on the wire, and records what the hook was
  // handed — the raw block must be the one request that completed, not
  // whatever else the client pipelined behind it.
  TPlainHost = class
  private
    FLock: TCriticalSection;
    FHits: Integer;
    FLastRaw: RawByteString;
  public
    constructor Create;
    destructor Destroy; override;
    // Matches TWSPlainRequestEvent; runs on the connection's execution
    // context, hence the lock around the two fields the battery reads.
    function Answer(const AHS: TWSServerHandshake;
      const ARawRequest: RawByteString; out AResponse: RawByteString): Boolean;
    procedure Snapshot(out AHits: Integer; out ALastRaw: RawByteString);
  end;

  TServerThread = class(TThread)
  public
    Srv: TWSServer;
    procedure Execute; override;
  end;

procedure TEcho.OnMsg(AConn: TWSConnection; AText: Boolean; P: PByte; Len: NativeInt);
begin
  if AText then AConn.SendText(P, Len) else AConn.SendBinary(P, Len);
end;

{ TPlainHost }

const
  PlainBodyTag: RawByteString = 'duetto-plain ';

// The one place the response bytes are defined — the hook returns them,
// the assertions rebuild them, so a mismatch is a real wire difference.
function PlainResponse(const AMethod, APath: string): RawByteString;
var
  Body: RawByteString;
begin
  Body := PlainBodyTag + AMethod + ' ' + APath;
  Result := 'HTTP/1.1 200 OK'#13#10 +
    'Content-Type: text/plain'#13#10 +
    'Connection: close'#13#10 +
    'Content-Length: ' + IntToStr(Length(Body)) + #13#10#13#10 + Body;
end;

constructor TPlainHost.Create;
begin
  inherited;
  FLock := TCriticalSection.Create;
end;

destructor TPlainHost.Destroy;
begin
  FLock.Free;
  inherited;
end;

function TPlainHost.Answer(const AHS: TWSServerHandshake;
  const ARawRequest: RawByteString; out AResponse: RawByteString): Boolean;
begin
  FLock.Acquire;
  try
    Inc(FHits);
    FLastRaw := ARawRequest;
  finally
    FLock.Release;
  end;
  AResponse := PlainResponse(AHS.Method, AHS.Path);
  Result := True;
end;

procedure TPlainHost.Snapshot(out AHits: Integer; out ALastRaw: RawByteString);
begin
  FLock.Acquire;
  try
    AHits := FHits;
    ALastRaw := FLastRaw;
  finally
    FLock.Release;
  end;
end;

procedure TServerThread.Execute;
begin
  // A transport/session exception would otherwise vanish into
  // FatalException until (never-reached) teardown; dump it at throw
  // time — dev-mode builds carry -gl, so frames resolve to file:line.
  // This trace is what pinned the mid-ingest use-after-free the win64
  // stress leg caught.
  try
    while not Terminated do
      Srv.Run(50);
  except
    on E: Exception do
    begin
      WriteLn('server thread exception: ', E.ClassName, ': ', E.Message);
      DumpExceptionBackTrace(Output);
      Flush(Output);
      raise;
    end;
  end;
end;

var
  Failures: Integer = 0;

var
  LastTick: QWord;

procedure Check(ACond: Boolean; const AName: string);
var
  Now_: QWord;
begin
  Now_ := GetTickCount64;
  if ACond then
    Write('ok   - ', AName)
  else
  begin
    Write('FAIL - ', AName);
    Inc(Failures);
  end;
  WriteLn('  [+', Now_ - LastTick, ' ms]');
  LastTick := Now_;
  Flush(Output);
end;

// ---------------------------------------------------------------------------
// Raw socket helpers for the violation section
// ---------------------------------------------------------------------------

// AReadTimeout = False leaves the socket without SO_RCVTIMEO. The TLS
// probe needs that: lwpt's blocking OpenSSL read treats a receive
// timeout as "retry" and would spin on it forever, where a plain block
// simply waits for the bytes or the hangup (the battery watchdog is the
// backstop). ARecvBuf > 0 shrinks SO_RCVBUF before the connect, which
// is how the backpressure probe forces the SERVER's egress to stall.
function RawConnectEx(APort: Word; AReadTimeout: Boolean;
  ARecvBuf: Integer = 0): Tsocket;
var
  SA: TInetSockAddr;
  {$ifdef WINDOWS}
  TimeoutMs: Cardinal;
  {$else}
  TV: TInteropTimeVal;
  {$endif}
begin
  Result := fpSocket(AF_INET, SOCK_STREAM, 0);
  if ARecvBuf > 0 then
    fpSetSockOpt(Result, SOL_SOCKET, SO_RCVBUF, @ARecvBuf, SizeOf(ARecvBuf));
  if AReadTimeout then
  begin
    {$ifdef WINDOWS}
    TimeoutMs := 5000;
    fpSetSockOpt(Result, SOL_SOCKET, SO_RCVTIMEO, @TimeoutMs,
      SizeOf(TimeoutMs));
    {$else}
    TV.Seconds := 5; TV.Microseconds := 0;
    fpSetSockOpt(Result, SOL_SOCKET, SO_RCVTIMEO, @TV, SizeOf(TV));
    {$endif}
  end;
  FillChar(SA, SizeOf(SA), 0);
  SA.sin_family := AF_INET;
  SA.sin_port := htons(APort);
  SA.sin_addr.s_addr := htonl($7F000001); // 127.0.0.1
  if fpConnect(Result, @SA, SizeOf(SA)) <> 0 then
  begin
    CloseSocket(Result); // the descriptor is ours until we raise past it
    raise Exception.Create('raw connect failed');
  end;
end;

function RawConnect(APort: Word): Tsocket;
begin
  Result := RawConnectEx(APort, True);
end;

// Speak the opening handshake on a raw socket; returns leftover bytes
// (frames pipelined behind the 101), if any.
function RawHandshake(AFd: Tsocket): TBytes;
var
  Req, Raw: RawByteString;
  Buf: array[0..4095] of Byte;
  Got, HdrEnd: Integer;
begin
  Result := nil;
  Req := ClientBuildRequest('127.0.0.1', '/', ClientGenerateKey, False);
  fpSend(AFd, @Req[1], Length(Req), 0);
  Raw := '';
  repeat
    Got := fpRecv(AFd, @Buf[0], SizeOf(Buf), 0);
    if Got <= 0 then raise Exception.Create('raw handshake: connection lost');
    SetLength(Raw, Length(Raw) + Got);
    Move(Buf[0], Raw[Length(Raw) - Got + 1], Got);
    HdrEnd := HandshakeFindEnd(Raw);
  until HdrEnd > 0;
  if Pos('101', Copy(Raw, 1, 16)) = 0 then
    raise Exception.Create('raw handshake: no 101');
  SetLength(Result, Length(Raw) - HdrEnd);
  if Length(Result) > 0 then
    Move(Raw[HdrEnd + 1], Result[0], Length(Result));
end;

// Read frames until a close frame arrives; return its status code
// (0 if the peer hung up without one).
function RawReadCloseCode(AFd: Tsocket; const ALeftover: TBytes): Word;
var
  Buf: TBytes;
  Len, Got, Used: NativeInt;
  H: TWSFrameHeader;
  R: TWSParseResult;
begin
  Result := 0;
  Buf := Copy(ALeftover);
  Len := Length(Buf);
  repeat
    R := ParseFrameHeader(PByte(Buf), Len, H);
    if R = wprOK then
    begin
      Used := H.HeaderLen;
      if Len - Used < H.PayloadLen then
        R := wprNeedMore // payload still in flight
      else if H.Opcode = WS_OP_CLOSE then
      begin
        if H.PayloadLen >= 2 then
          Exit((Buf[Used] shl 8) or Buf[Used + 1])
        else
          Exit(0);
      end
      else
      begin // skip non-close frame (e.g. an echo) and continue
        Delete(Buf, 0, Used + H.PayloadLen);
        Dec(Len, Used + H.PayloadLen);
        Continue;
      end;
    end;
    if R = wprProtocolError then Exit(0);
    SetLength(Buf, Len + 4096);
    Got := fpRecv(AFd, @Buf[Len], 4096, 0);
    if Got <= 0 then Exit(0); // EOF/timeout without close frame
    Len := Len + Got;
    SetLength(Buf, Len);
  until False;
end;

// One complete frame as bytes — the wire form both the raw-socket and
// the TLS probe senders push, so the two cannot drift apart.
function BuildFrameBytes(AOpcode: Byte; const APayload: RawByteString;
  AMasked: Boolean): RawByteString;
var
  Hdr: array[0..WS_MAX_HEADER - 1] of Byte;
  HLen: Integer;
  Key: UInt32;
  Body: TBytes;
begin
  Key := $A1B2C3D4;
  HLen := WriteFrameHeader(@Hdr[0], True, False, AOpcode, AMasked, Key,
    Length(APayload));
  SetLength(Result, HLen + Length(APayload));
  Move(Hdr[0], Result[1], HLen);
  if APayload = '' then Exit;
  SetLength(Body, Length(APayload));
  Move(APayload[1], Body[0], Length(APayload));
  if AMasked then
    ApplyMask(PByte(Body), Length(Body), Key, 0);
  Move(Body[0], Result[HLen + 1], Length(Body));
end;

// False = the peer is already gone (the send failed or went short). Only
// the abrupt-drop workers act on it; the violation sections below send
// into a socket the server has just accepted, where a failure would
// surface as the missing close code they assert anyway.
function RawSendFrame(AFd: Tsocket; AOpcode: Byte; const APayload: RawByteString;
  AMasked: Boolean): Boolean;
var
  Wire: RawByteString;
begin
  Wire := BuildFrameBytes(AOpcode, APayload, AMasked);
  Result := fpSend(AFd, @Wire[1], Length(Wire), 0) = Length(Wire);
end;

// Read until the peer closes; AEof distinguishes a real EOF from the
// 5 s SO_RCVTIMEO expiring (which would mean the server never hung up).
function RawReadToEof(AFd: Tsocket; out AEof: Boolean): RawByteString;
var
  Buf: array[0..4095] of Byte;
  Got: Integer;
begin
  Result := '';
  repeat
    Got := fpRecv(AFd, @Buf[0], SizeOf(Buf), 0);
    if Got <= 0 then Break;
    SetLength(Result, Length(Result) + Got);
    Move(Buf[0], Result[Length(Result) - Got + 1], Got);
  until False;
  AEof := Got = 0;
end;

// ---------------------------------------------------------------------------
// Server TLS section helpers (Linux; duetto#22)
// ---------------------------------------------------------------------------

{$ifdef LINUX}

const
  TlsPassphrase = 'duetto-interop';
  // Deliberately at lwpt's floor so a 512 KiB message is chopped into
  // ~30 input windows: every one of them exercises the accepted-prefix
  // re-offer path, and a single lost, duplicated or reordered byte
  // would break the record stream outright.
  TlsInputHighWater = 17 * 1024;
  TlsOutputCapacity = 17 * 1024;
  // Short enough to assert against inside a battery, long enough that a
  // loaded CI box cannot trip it with a real handshake.
  TlsHandshakeDeadlineMs = 700;
  TlsInboundBudget = 20 * 1024;
  TlsBigEchoBytes = 512 * 1024;
  TlsCloseBoundMs = 4000;
  // Backpressure probe: a deliberately tiny receive buffer on the
  // client side so the SERVER's socket backs up after a few kilobytes
  // of echo, which is what stalls its decryption and fills the
  // encrypted-input window. The burst total stays far below the
  // send-side headroom (server receive buffer plus client send buffer)
  // so the probe's own write never blocks against the paused server.
  TlsBurstRecvBuf = 64 * 1024;
  TlsBurstLeadSize = 256 * 1024;
  TlsBurstTailCount = 8;
  TlsBurstTailSize = 4096;
  // MSG_NOSIGNAL: the flood probe keeps writing into a socket the
  // server is entitled to drop mid-write, and SIGPIPE would kill the
  // battery instead of failing a check.
  TlsSendFlags = $4000;

// setenv, not the RTL: OpenSSL reads SSL_CERT_FILE through libc getenv
// when SSL_CTX_set_default_verify_paths loads the trust store, so the
// value has to land in the C environment (and before the first client
// TLS use, which is why the whole section runs after it).
function C_setenv(AName: PAnsiChar; AValue: PAnsiChar;
  AOverwrite: Integer): Integer; cdecl; external name 'setenv';

function TlsOpenSslPresent: Boolean;
begin
  try
    Result := ExecuteProcess('/bin/sh',
      ['-c', 'command -v openssl >/dev/null 2>&1']) = 0;
  except
    Result := False;
  end;
end;

// A throwaway CA and a leaf it signs, in ADir. Strict identity
// validation in lwpt rejects self-signed leaves, so a real two-level
// chain is required; the leaf carries serverAuth plus the localhost /
// 127.0.0.1 names the client verifies against.
function TlsGenerateIdentity(const ADir: string): Boolean;
var
  Cnf: TStringList;
  Script: string;
begin
  Result := False;
  if not ForceDirectories(ADir) then Exit;
  Cnf := TStringList.Create;
  try
    Cnf.Add('[ext]');
    // The literal-IP DNS entry is deliberate: OpenSSL's hostname check
    // (the only one lwpt's client configures) matches DNS names by
    // string, never IP SANs, and the battery must reach the listener
    // without depending on a resolver that a bare container may not
    // have. Test-certificate liberty, nothing a real identity would do.
    Cnf.Add('subjectAltName = DNS:localhost, DNS:127.0.0.1, IP:127.0.0.1');
    Cnf.Add('basicConstraints = CA:FALSE');
    Cnf.Add('keyUsage = digitalSignature, keyEncipherment');
    Cnf.Add('extendedKeyUsage = serverAuth');
    try
      Cnf.SaveToFile(ADir + 'leaf.cnf');
    except
      Exit;
    end;
  finally
    Cnf.Free;
  end;
  Script :=
    'set -e; cd "' + ADir + '"; ' +
    'openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes ' +
    '-keyout ca.key -out ca.crt -subj /CN=duetto-interop-ca ' +
    '-addext basicConstraints=critical,CA:TRUE ' +
    '-addext keyUsage=critical,keyCertSign,cRLSign; ' +
    'openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key ' +
    '-out leaf.csr -subj /CN=localhost; ' +
    'openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key ' +
    '-CAcreateserial -out leaf.crt -days 2 -sha256 ' +
    '-extfile leaf.cnf -extensions ext; ' +
    'openssl pkcs12 -export -out identity.p12 -inkey leaf.key ' +
    '-in leaf.crt -certfile ca.crt -passout pass:' + TlsPassphrase;
  try
    // Braces, not a trailing redirect: the redirect has to cover every
    // command in the script, and openssl chatters on both streams.
    ExecuteProcess('/bin/sh',
      ['-c', '{ ' + Script + '; } >' + ADir + 'openssl.log 2>&1']);
  except
    Exit;
  end;
  Result := FileExists(ADir + 'identity.p12') and FileExists(ADir + 'ca.crt');
end;

// Raw TLS probe. TWSClient closes its socket as part of Close(), so an
// orderly TLS shutdown is invisible from there; this speaks the
// opening handshake and the frame layer directly over lwpt's client
// TLS so the close_notify can be observed.
function TlsProbeWrite(var ATls: TTransportSecurityConnection;
  const AData: RawByteString): Boolean;
begin
  Result := TransportSecurityWrite(ATls, @AData[1], Length(AData)) =
    Length(AData);
end;

function TlsProbeHandshake(var ATls: TTransportSecurityConnection;
  APort: Word): TBytes;
var
  Req, Raw: RawByteString;
  Buf: array[0..4095] of Byte;
  Got, HdrEnd: Integer;
begin
  Result := nil;
  Req := ClientBuildRequest('127.0.0.1:' + IntToStr(APort), '/',
    ClientGenerateKey, False);
  if not TlsProbeWrite(ATls, Req) then
    raise Exception.Create('tls probe: handshake send failed');
  Raw := '';
  repeat
    Got := TransportSecurityRead(ATls, Buf, SizeOf(Buf));
    if Got <= 0 then raise Exception.Create('tls probe: connection lost');
    SetLength(Raw, Length(Raw) + Got);
    Move(Buf[0], Raw[Length(Raw) - Got + 1], Got);
    HdrEnd := HandshakeFindEnd(Raw);
  until HdrEnd > 0;
  if Pos('101', Copy(Raw, 1, 16)) = 0 then
    raise Exception.Create('tls probe: no 101');
  SetLength(Result, Length(Raw) - HdrEnd);
  if Length(Result) > 0 then
    Move(Raw[HdrEnd + 1], Result[0], Length(Result));
end;

function TlsProbeReadCloseCode(var ATls: TTransportSecurityConnection;
  const ALeftover: TBytes): Word;
var
  Buf: TBytes;
  Len, Got, Used: NativeInt;
  H: TWSFrameHeader;
  R: TWSParseResult;
begin
  Result := 0;
  Buf := Copy(ALeftover);
  Len := Length(Buf);
  repeat
    R := ParseFrameHeader(PByte(Buf), Len, H);
    if R = wprOK then
    begin
      Used := H.HeaderLen;
      if Len - Used < H.PayloadLen then
        R := wprNeedMore
      else if H.Opcode = WS_OP_CLOSE then
      begin
        if H.PayloadLen >= 2 then
          Exit((Buf[Used] shl 8) or Buf[Used + 1])
        else
          Exit(0);
      end
      else
      begin
        Delete(Buf, 0, Used + H.PayloadLen);
        Dec(Len, Used + H.PayloadLen);
        Continue;
      end;
    end;
    if R = wprProtocolError then Exit(0);
    SetLength(Buf, Len + 4096);
    Got := TransportSecurityRead(ATls, PByte(@Buf[Len])^, 4096);
    if Got <= 0 then Exit(0);
    Len := Len + Got;
    SetLength(Buf, Len);
  until False;
end;

// True when the peer's TLS layer shut down in an orderly way: lwpt's
// blocking read returns 0 on close_notify and RAISES on a reset or a
// bare FIN, so this is exactly the distinction the check needs.
function TlsProbeSawCloseNotify(var ATls: TTransportSecurityConnection): Boolean;
var
  Buf: array[0..255] of Byte;
begin
  try
    Result := TransportSecurityRead(ATls, Buf, SizeOf(Buf)) = 0;
  except
    Result := False;
  end;
end;

// One burst message, distinct per index so a reordered or duplicated
// echo cannot pass the compare.
function TlsBurstPayload(AIndex, ASize: Integer): RawByteString;
var
  I: Integer;
begin
  SetLength(Result, ASize);
  for I := 1 to ASize do
    Result[I] := AnsiChar(Byte((AIndex * 7 + I * 31 + 13) and $FF));
end;

// Verify the next echoes, in order, against the payloads their indices
// generate. Used by the backpressure probe, where every byte has to
// come back exactly once and in sequence across an input pause.
function TlsProbeVerifyEchoes(var ATls: TTransportSecurityConnection;
  const ALeftover: TBytes; const ASizes: array of Integer): Boolean;
var
  Buf: TBytes;
  Len, Got, Used: NativeInt;
  H: TWSFrameHeader;
  R: TWSParseResult;
  Index: Integer;
  Want: RawByteString;
begin
  Buf := Copy(ALeftover);
  Len := Length(Buf);
  Index := 0;
  while Index <= High(ASizes) do
  begin
    R := ParseFrameHeader(PByte(Buf), Len, H);
    if (R = wprOK) and (Len - H.HeaderLen >= H.PayloadLen) then
    begin
      Used := H.HeaderLen;
      if H.Opcode = WS_OP_BINARY then
      begin
        Want := TlsBurstPayload(Index, ASizes[Index]);
        if (H.PayloadLen <> ASizes[Index]) or
          (not CompareMem(@Buf[Used], @Want[1], ASizes[Index])) then
          Exit(False);
        Inc(Index);
      end;
      Delete(Buf, 0, Used + H.PayloadLen);
      Dec(Len, Used + H.PayloadLen);
      Continue;
    end;
    if R = wprProtocolError then Exit(False);
    SetLength(Buf, Len + 65536);
    Got := TransportSecurityRead(ATls, PByte(@Buf[Len])^, 65536);
    if Got <= 0 then Exit(False);
    Len := Len + Got;
    SetLength(Buf, Len);
  end;
  Result := True;
end;

// Wait for the server to hang up on a raw (non-TLS) socket. Returns the
// elapsed milliseconds, or -1 when it never did within ABoundMs.
function RawWaitForClose(AFd: Tsocket; ABoundMs: Integer): Integer;
var
  Buf: array[0..1023] of Byte;
  Got: Integer;
  Start: QWord;
begin
  Start := GetTickCount64;
  repeat
    // EOF (0) and RST (-1) both mean "dropped"; the socket carries a
    // 5 s SO_RCVTIMEO, so anything under the (much smaller) bound the
    // caller asserts can only be a real drop.
    Got := fpRecv(AFd, @Buf[0], SizeOf(Buf), 0);
    if Got <= 0 then Exit(Integer(GetTickCount64 - Start));
  until GetTickCount64 - Start > QWord(ABoundMs);
  Result := -1;
end;

{$endif}

// ---------------------------------------------------------------------------
// Concurrent-connections stress section
// ---------------------------------------------------------------------------
// 33 client threads against the one server instance — 28 echo workers
// looping connect / single echo / pipelined burst / clean close, 4
// abrupt-drop workers killing raw sockets mid-conversation (no closing
// handshake), and one pusher thread Posting server-initiated messages
// into every live connection while the clients are reading. Framing
// keeps the two streams distinguishable — binary frames are echoes, text
// frames are pushes — so each worker verifies its echo payloads
// round-trip intact and in order while push serials stay consecutive per
// connection.
//
// No timing assertions: the wall-clock budget and the cycle caps only
// bound how long the loops run (whichever ends first), and the only
// failure clock is a generous stall limit so a wedged stream fails
// instead of hanging CI. Payloads are derived from (seed, cycle,
// message index) rather than a random source — reproducible given the
// same cycle, though which payloads a run actually sends depends on how
// many cycles the budget allowed.

const
  StressEchoWorkerCount = 28;
  StressDropWorkerCount = 4;
  StressLingerCount = 4;
  StressBudgetMs = 3000;
  StressBurstLen = 4;
  StressReadSliceMs = 1000;
  StressStallLimitMs = 30000;
  StressConnectAttempts = 5;
  StressPayloadMin = 64;
  StressPayloadSpread = 1400;
  // Connection-churn caps. Every cleanly closed loopback connection
  // parks a TIME_WAIT entry for 2*MSL (30 s on macOS) in the same
  // ~16 k ephemeral-port range both ends share, so uncapped reconnect
  // cycles make connect() fail process-wide a few consecutive runs
  // later. The caps keep a whole run under ~1 k such entries; the
  // drop workers contribute none (RST via SO_LINGER 0).
  StressEchoCycleCap = 30;
  StressDropCycleCap = 150;
  StressDropPauseMs = 5;
  // Whole-section watchdog: storm budget plus generous headroom for a
  // slow CI VM. Purely a wedge detector, never a speed assertion.
  StressWatchdogMs = StressBudgetMs + 120000;
  StressPushTail: RawByteString = 'duetto-push';

type
  // Holds connection references from OnOpen until OnClientClose returns
  // — exactly the window the TWSConnection.Post lifetime contract
  // allows. PushSweep Posts while holding the lock: a connection
  // dropping concurrently blocks in HandleClose until the sweep ends,
  // so the reference stays allocated, and the server re-validates it
  // against its registry anyway (a stale Post is silently discarded).
  TStressTracker = class
  private
    FLock: TCriticalSection;
    FConns: array of TWSConnection;
    FCount: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure HandleOpen(AConn: TWSConnection);
    procedure HandleClose(AConn: TWSConnection);
    procedure PushToConn(AConn: TWSConnection);
    procedure PushSweep;
    procedure Clear;
  end;

  TStressWorker = class(TThread)
  public
    // Points at the main thread's deadline, written immediately after
    // the last worker starts so the wall-clock budget covers the window
    // in which every worker is actually running (a worker scheduled late
    // would otherwise burn its budget before its first cycle). Read per
    // iteration. Unsynchronised on purpose: whatever a torn read on a
    // 32-bit leg yields (including a value off by 2^32 ms if the low
    // dword wraps between the two writes), the loops stay bounded by
    // the cycle caps and the repeat-until guarantees one cycle, and
    // nothing asserts on elapsed time — so no torn value can produce a
    // false failure.
    DeadlinePtr: PQWord;
    Cycles: Integer;
    Ok: Boolean;
    FailMsg: string;
    procedure MarkFailed(const AMsg: string);
  end;

  TStressEchoWorker = class(TStressWorker)
  private
    FNextPushSerial: NativeUInt;
    function BuildPayload(AMsgIdx: Integer): TBytes;
    procedure VerifyPush(const AData: TBytes);
    procedure EchoRound(ACli: TWSClient; ACount: Integer;
      var AMsgIdx: Integer);
  public
    Seed: Integer;
    Url: string;
    Pushes: Integer;
    // Push-stream correctness is tracked apart from echo correctness so
    // a serial violation composes into the push check instead of failing
    // the echo check line.
    PushOk: Boolean;
    PushFailMsg: string;
    // Decremented on exit; the pusher and the drop workers use it to
    // leave once there is no echo traffic left to race.
    LiveEchoPtr: PLongInt;
    procedure MarkPushFailed(const AMsg: string);
    procedure Execute; override;
  end;

  TStressDropWorker = class(TStressWorker)
  public
    Seed: Integer;
    Port: Word;
    // Caught transient failures (loopback churn). Reported, not fatal —
    // only a consecutive streak fails the worker.
    TransientTotal: Integer;
    LiveEchoPtr: PLongInt;
    procedure Execute; override;
  end;

  TStressPusher = class(TThread)
  public
    Tracker: TStressTracker;
    DeadlinePtr: PQWord;
    LiveEchoPtr: PLongInt;
    Ok: Boolean;
    FailMsg: string;
    procedure Execute; override;
  end;

  // Converts a wedged server into a fast, attributable failure: a dead
  // accept path leaves TCP connects completing against the kernel
  // backlog while the 101 never arrives, which blocks the client's
  // unbounded Connect — and would hang the process (and a CI job)
  // until an external timeout with no output. If the section has not
  // signalled completion inside the watchdog bound, report and
  // hard-exit.
  TStressWatchdog = class(TThread)
  public
    // Written by the main thread, polled here. No atomics: the poll loop
    // reloads it after Sleep, an opaque call the compiler cannot hoist
    // the load across, and a missed update costs at most one 250 ms
    // slice — the flag only ever transitions False -> True.
    Done: PBoolean;
    Srv: TThread;   // the server thread, for FatalException on expiry
    // Last phase marker the main thread recorded. ShortString on
    // purpose: value semantics, no refcounted heap pointer, so a torn
    // cross-thread read garbles the text at worst instead of crashing.
    Phase: ^ShortString;
    procedure Execute; override;
  end;

// Connect with a bounded retry: loopback churn can drop the odd SYN or
// leave the ephemeral-port range momentarily tight; a persistent
// refusal still surfaces as the original exception.
function StressConnect(const AUrl: string): TWSClient;
var
  Attempt: Integer;
begin
  Attempt := 0;
  repeat
    Inc(Attempt);
    Result := TWSClient.Create;
    try
      Result.Connect(AUrl);
      Exit;
    except
      on E: EWSClient do
      begin
        FreeAndNil(Result);
        if Attempt >= StressConnectAttempts then raise;
        Sleep(10 * Attempt);
      end;
      // Anything else is not a retryable connect failure, but the client
      // is still ours until it is returned — free it, then let it out.
      on E: Exception do
      begin
        FreeAndNil(Result);
        raise;
      end;
    end;
  until False;
end;

{ TStressTracker }

constructor TStressTracker.Create;
begin
  inherited;
  FLock := TCriticalSection.Create;
end;

destructor TStressTracker.Destroy;
begin
  FLock.Free;
  inherited;
end;

procedure TStressTracker.HandleOpen(AConn: TWSConnection);
begin
  FLock.Acquire;
  try
    if FCount = Length(FConns) then
      SetLength(FConns, FCount + 32);
    FConns[FCount] := AConn;
    Inc(FCount);
  finally
    FLock.Release;
  end;
end;

procedure TStressTracker.HandleClose(AConn: TWSConnection);
var
  I: Integer;
begin
  FLock.Acquire;
  try
    for I := 0 to FCount - 1 do
      if FConns[I] = AConn then
      begin
        FConns[I] := FConns[FCount - 1];
        FConns[FCount - 1] := nil;
        Dec(FCount);
        Break;
      end;
  finally
    FLock.Release;
  end;
end;

// Runs on the connection's callback context, serialized with its
// OnMessage — so the per-connection serial can live lock-free in
// UserData, and the receiver can assert the serials it sees are exactly
// 0, 1, 2, ... for the lifetime of the connection.
procedure TStressTracker.PushToConn(AConn: TWSConnection);
var
  Serial: NativeUInt;
  Payload: RawByteString;
begin
  Serial := NativeUInt(AConn.UserData);
  AConn.UserData := Pointer(Serial + 1);
  Payload := 'P' + IntToStr(Serial) + ':' + StressPushTail;
  // False = dropped and freed mid-call; AConn is not touched again.
  AConn.SendText(@Payload[1], Length(Payload));
end;

procedure TStressTracker.PushSweep;
var
  I: Integer;
begin
  FLock.Acquire;
  try
    for I := 0 to FCount - 1 do
      FConns[I].Post(PushToConn);
  finally
    FLock.Release;
  end;
end;

// TWSServer.Destroy tears the registry down directly and never fires
// OnClientClose, so entries the tracker still holds would dangle past
// the server's free. Nothing reads them afterwards today (the pusher is
// long joined), but a tracker outliving the server must not be left
// pointing at freed connections.
procedure TStressTracker.Clear;
begin
  FLock.Acquire;
  try
    FConns := nil;
    FCount := 0;
  finally
    FLock.Release;
  end;
end;

{ TStressWorker }

procedure TStressWorker.MarkFailed(const AMsg: string);
begin
  if Ok then
  begin
    Ok := False;
    FailMsg := AMsg;
  end;
end;

{ TStressEchoWorker }

procedure TStressEchoWorker.MarkPushFailed(const AMsg: string);
begin
  if PushOk then
  begin
    PushOk := False;
    PushFailMsg := AMsg;
  end;
end;

function TStressEchoWorker.BuildPayload(AMsgIdx: Integer): TBytes;
var
  Len, J: Integer;
begin
  Len := StressPayloadMin +
    ((Seed * 131 + Cycles * 29 + AMsgIdx * 17) mod StressPayloadSpread);
  SetLength(Result, Len);
  for J := 0 to Len - 1 do
    Result[J] := Byte((Seed + Cycles * 31 + AMsgIdx * 7 + J * 13) and $FF);
end;

procedure TStressEchoWorker.VerifyPush(const AData: TBytes);
var
  I, Colon: Integer;
  SerialText: string;
  Serial: Int64;
begin
  Colon := 0;
  if (Length(AData) >= 2) and (AData[0] = Ord('P')) then
    for I := 1 to Length(AData) - 1 do
      if AData[I] = Ord(':') then
      begin
        Colon := I;
        Break;
      end;
  if Colon < 2 then
  begin
    MarkPushFailed('malformed push frame');
    Exit;
  end;
  SetLength(SerialText, Colon - 1);
  Move(AData[1], SerialText[1], Colon - 1);
  Serial := StrToInt64Def(SerialText, -1);
  if Serial <> Int64(FNextPushSerial) then
  begin
    MarkPushFailed(Format('push serial %s, expected %d',
      [SerialText, Int64(FNextPushSerial)]));
    // Resynchronise so one gap reports once instead of cascading.
    if Serial >= 0 then FNextPushSerial := NativeUInt(Serial) + 1;
    Exit;
  end;
  if (Length(AData) - Colon - 1 <> Length(StressPushTail)) or
    not CompareMem(@AData[Colon + 1], @StressPushTail[1],
      Length(StressPushTail)) then
  begin
    MarkPushFailed('push tail corrupt');
    Exit;
  end;
  Inc(FNextPushSerial);
  Inc(Pushes);
end;

// Send ACount pipelined binary messages, then read until every echo is
// back — intact and in order — verifying any text push that interleaves.
procedure TStressEchoWorker.EchoRound(ACli: TWSClient; ACount: Integer;
  var AMsgIdx: Integer);
var
  Sent: array of TBytes;
  I, GotCount: Integer;
  IsText: Boolean;
  Data: TBytes;
  LastEchoTick: QWord;
begin
  SetLength(Sent, ACount);
  for I := 0 to ACount - 1 do
  begin
    Sent[I] := BuildPayload(AMsgIdx + I);
    ACli.SendBinary(@Sent[I][0], Length(Sent[I]));
  end;
  GotCount := 0;
  // Wall clock since the last *echo*, not since the last message of any
  // kind: the pusher keeps text arriving on this connection throughout,
  // so a stall clock that any message resets — or one that only ticks on
  // read timeouts, which pushes prevent from ever happening — would let
  // a wedged echo stream hide behind live push traffic forever.
  LastEchoTick := GetTickCount64;
  while Ok and (GotCount < ACount) do
  begin
    case ACli.ReadMessage(IsText, Data, StressReadSliceMs) of
      wrrMessage:
        if IsText then
          VerifyPush(Data)
        else
        begin
          LastEchoTick := GetTickCount64;
          if (Length(Data) <> Length(Sent[GotCount])) or
            not CompareMem(@Data[0], @Sent[GotCount][0], Length(Data)) then
            MarkFailed(Format('echo corrupt (cycle %d, message %d)',
              [Cycles, AMsgIdx + GotCount]))
          else
            Inc(GotCount);
        end;
      wrrTimeout: ; // nothing readable this slice; the clock below judges
      wrrClosed:
        MarkFailed(Format('connection closed mid-echo (code %d)',
          [ACli.CloseCode]));
    end;
    if GetTickCount64 - LastEchoTick >= StressStallLimitMs then
      MarkFailed('echo stream stalled');
  end;
  Inc(AMsgIdx, ACount);
end;

procedure TStressEchoWorker.Execute;
var
  Cli: TWSClient;
  MsgIdx: Integer;
begin
  Ok := True;
  PushOk := True;
  try
    // repeat, not while: however late this thread is scheduled, it
    // completes at least one cycle, so Cycles = 0 means the worker never
    // ran rather than "the budget was already spent when it woke up".
    repeat
      Cli := StressConnect(Url);
      try
        FNextPushSerial := 0;
        MsgIdx := 0;
        EchoRound(Cli, 1, MsgIdx);
        if Ok then
          EchoRound(Cli, StressBurstLen, MsgIdx);
        if Ok then
        begin
          Cli.Close(1000, '');
          if Cli.CloseCode <> 1000 then
            MarkFailed(Format('clean close echoed %d, expected 1000',
              [Cli.CloseCode]));
        end;
      finally
        Cli.Free;
      end;
      Inc(Cycles);
    until (not Ok) or (GetTickCount64 >= DeadlinePtr^) or
      (Cycles >= StressEchoCycleCap);
  except
    on E: Exception do
      MarkFailed(E.ClassName + ': ' + E.Message);
  end;
  InterlockedDecrement(LiveEchoPtr^);
end;

{ TStressDropWorker }

procedure TStressDropWorker.Execute;
var
  Fd: Tsocket;
  Payload: RawByteString;
  HardClose: TInteropLinger;
  Transient: Integer;
begin
  Ok := True;
  Transient := 0;
  // SO_LINGER 0 turns CloseSocket into a hard RST: the most abrupt
  // teardown TCP offers, and it parks no TIME_WAIT entries that would
  // starve the shared loopback port range across runs.
  HardClose.OnOff := 1;
  HardClose.Seconds := 0;
  repeat
    try
      Fd := RawConnect(Port);
      try
        fpSetSockOpt(Fd, SOL_SOCKET, SO_LINGER, @HardClose,
          SizeOf(HardClose));
        RawHandshake(Fd);
        if (Cycles and 1) = 0 then
        begin
          // Two echoes in flight when the socket dies; odd cycles die
          // straight after the 101 so teardown races the open path too.
          // A send that fails just means this peer died first — that
          // ends the cycle, it is not a battery failure.
          Payload := 'abrupt-' + IntToStr(Seed) + '-' + IntToStr(Cycles);
          if RawSendFrame(Fd, WS_OP_BINARY, Payload, True) then
            RawSendFrame(Fd, WS_OP_BINARY, Payload, True);
        end;
        // No closing handshake: the RST lands while the echoes (and any
        // pushes) are still in flight server-side.
      finally
        CloseSocket(Fd);
      end;
      Inc(Cycles);
      Transient := 0;
    except
      on E: Exception do
      begin
        // Loopback churn can drop the odd SYN or handshake read; only a
        // persistent streak is a failure.
        Inc(Transient);
        Inc(TransientTotal);
        if Transient >= StressConnectAttempts then
          MarkFailed(E.ClassName + ': ' + E.Message);
      end;
    end;
    Sleep(StressDropPauseMs);
    // Once the last echo worker is gone there is no live traffic left to
    // drop against; the deadline stays the upper bound.
  until (not Ok) or (GetTickCount64 >= DeadlinePtr^) or
    (Cycles >= StressDropCycleCap) or (LiveEchoPtr^ <= 0);
end;

{ TStressPusher }

procedure TStressPusher.Execute;
begin
  Ok := True;
  // Same guard as the other workers: an exception here would otherwise
  // sit in FatalException and read as a silent no-push run.
  try
    // Sweeping past the last echo worker's exit only pushes into the
    // linger connections; the deadline stays the upper bound.
    while (not Terminated) and (GetTickCount64 < DeadlinePtr^) and
      (LiveEchoPtr^ > 0) do
    begin
      Tracker.PushSweep;
      Sleep(1);
    end;
  except
    on E: Exception do
    begin
      Ok := False;
      FailMsg := E.ClassName + ': ' + E.Message;
    end;
  end;
end;

procedure TStressWatchdog.Execute;
var
  Waited: Integer;
begin
  Waited := 0;
  while Waited < StressWatchdogMs do
  begin
    Sleep(250);
    Inc(Waited, 250);
    if Done^ then Exit;
  end;
  if Done^ then Exit; // completion at the boundary is not an expiry
  WriteLn('FAIL - stress: watchdog expired after ', StressWatchdogMs,
    ' ms; section did not complete (wedged server, or pathological ',
    'slowness — per-worker diagnostics were discarded)');
  WriteLn('       phase: ', Phase^);
  if (Srv <> nil) and (Srv.FatalException <> nil) then
    WriteLn('       server thread died: ',
      Exception(Srv.FatalException).Message)
  else
    WriteLn('       server thread alive (no FatalException)');
  Flush(Output);
  // Raw process exit, not Halt: Halt runs unit finalization on this
  // secondary thread while the main thread is wedged inside the very
  // subsystem being finalized — the watchdog would hang exactly where
  // it is supposed to cut through. The diagnostics above are already
  // flushed, so there is nothing left worth unwinding for.
  {$ifdef WINDOWS}
  ExitProcess(2);
  {$else}
  fpExit(2);
  {$endif}
end;

// ---------------------------------------------------------------------------

const
  HelloProbe: RawByteString = 'hello duetto';
  PipelinedMsgs: array[0..2] of RawByteString = ('one', 'two', 'three');
  LingerProbe: RawByteString = 'linger';

var
  Echo: TEcho;
  SrvT: TServerThread;
  Port: Word;
  Url: string;
  Cli: TWSClient;
  IsText: Boolean;
  Data: TBytes;
  Big: TBytes;
  S: RawByteString;
  I: Integer;
  Ok: Boolean;
  Fd: Tsocket;
  Left: TBytes;
  Code: Word;
  Tracker: TStressTracker;
  Pusher: TStressPusher;
  EchoWorkers: array[0..StressEchoWorkerCount - 1] of TStressEchoWorker;
  DropWorkers: array[0..StressDropWorkerCount - 1] of TStressDropWorker;
  Linger: array[0..StressLingerCount - 1] of TWSClient;
  LingerOk: array[0..StressLingerCount - 1] of Boolean;
  LingerVerified: Integer;
  LingerBad: string;
  Deadline: QWord;
  LiveEcho: LongInt;
  Watchdog: TStressWatchdog;
  StressDone: Boolean;
  StressPhase: ShortString;
  TotalCycles, TotalPushes, TotalDrops, TotalTransient: Integer;
  AllOk, PushAllOk: Boolean;
  // Plain-request section
  PlainHost: TPlainHost;
  PlainSrvT: TServerThread;
  PlainPort: Word;
  PlainReq, PlainGot, PlainWant, PlainRaw: RawByteString;
  PlainHits, PlainHitsBefore: Integer;
  Eof: Boolean;
  ReadRes: TWSReadResult;
  {$ifdef LINUX}
  // Server-TLS section
  TlsDir, TlsUrl: string;
  TlsCfg: TWSTransportTls;
  TlsSrvT: TServerThread;
  TlsCli: TWSClient;
  TlsPort: Word;
  TlsProbe: TTransportSecurityConnection;
  TlsProbeFd: Tsocket;
  TlsLeft, Garbage: TBytes;
  TlsSizes: array of Integer;
  TlsCode: Word;
  TlsElapsed: Integer;
  TlsOk: Boolean;
  {$endif}
begin
  Echo := TEcho.Create;
  Tracker := TStressTracker.Create;
  SrvT := TServerThread.Create(True);
  SrvT.Srv := TWSServer.Create(0, True); // port 0 = kernel-assigned
  SrvT.Srv.OnMessage := Echo.OnMsg;
  // Wired before the server thread starts so the method-pointer writes
  // can never tear against a concurrent open/close; the tracker idles
  // through the single-connection sections and matters for the stress.
  SrvT.Srv.OnOpen := Tracker.HandleOpen;
  SrvT.Srv.OnClientClose := Tracker.HandleClose;
  Port := SrvT.Srv.Port;
  Url := Format('ws://127.0.0.1:%d/', [Port]);
  SrvT.Start;
  WriteLn('server on ', Port);
  Flush(Output);
  LastTick := GetTickCount64;

  // The watchdog covers the whole battery, not just the storm: every
  // section before it also blocks in unbounded Connect/ReadMessage calls
  // that a wedged accept path would hang forever. Same overall bound —
  // it simply starts counting at the first connect instead of the last
  // section, and the phase marker says where the process got stuck.
  StressDone := False;
  StressPhase := 'single-connection sections';
  Watchdog := TStressWatchdog.Create(True);
  Watchdog.Done := @StressDone;
  Watchdog.Srv := SrvT;
  Watchdog.Phase := @StressPhase;
  Watchdog.Start;

  // --- duetto client vs duetto server ---------------------------------------
  Cli := TWSClient.Create;
  Cli.Connect(Url);
  Cli.SendText(HelloProbe);
  Check(Cli.ReadMessage(IsText, Data) and IsText and
    (Length(Data) = Length(HelloProbe)) and
    CompareMem(@Data[0], @HelloProbe[1], Length(HelloProbe)),
    'text echo round-trip');

  SetLength(Big, 1024 * 1024);
  for I := 0 to High(Big) do
    Big[I] := Byte((I * 31 + 7) and $FF);
  Cli.SendBinary(@Big[0], Length(Big));
  Check(Cli.ReadMessage(IsText, Data) and (not IsText) and
    (Length(Data) = Length(Big)) and CompareMem(@Data[0], @Big[0], Length(Big)),
    'binary echo 1 MiB');

  Cli.SendText('one');
  Cli.SendText('two');
  Cli.SendText('three');
  Ok := True;
  for I := 0 to 2 do
  begin
    S := PipelinedMsgs[I];
    Ok := Ok and Cli.ReadMessage(IsText, Data) and IsText and
      (Length(Data) = Length(S)) and CompareMem(@Data[0], @S[1], Length(S));
  end;
  Check(Ok, 'three pipelined messages, in order');

  Cli.Ping('beat');
  Cli.SendText('after ping');
  Check(Cli.ReadMessage(IsText, Data) and (Length(Data) = 10),
    'ping auto-ponged, data stream undisturbed');

  Cli.Close(1000, 'done');
  Check(Cli.CloseCode = 1000, 'clean close echoes 1000');
  Cli.Free;

  // --- bounded ReadMessage (ws:// only) -----------------------------------
  StressPhase := 'bounded-read section';
  Cli := TWSClient.Create;
  Cli.Connect(Url);
  // Nothing in flight: the bounded form must come back and say so. Only
  // the outcome is asserted — how quickly it returns is not a contract.
  Check(Cli.ReadMessage(IsText, Data, 200) = wrrTimeout,
    'bounded read on an idle stream reports wrrTimeout');

  // ATimeoutMs = 0 is a pure poll, never a wait, so it keeps reporting
  // wrrTimeout until the echo has actually landed in the queue. Polling
  // until it does is what proves the queued case returns wrrTimeout's
  // opposite without the call ever blocking.
  Cli.SendText(HelloProbe);
  Deadline := GetTickCount64 + StressStallLimitMs;
  repeat
    ReadRes := Cli.ReadMessage(IsText, Data, 0);
    if ReadRes = wrrTimeout then Sleep(1);
  until (ReadRes <> wrrTimeout) or (GetTickCount64 >= Deadline);
  Check((ReadRes = wrrMessage) and IsText and
    (Length(Data) = Length(HelloProbe)) and
    CompareMem(@Data[0], @HelloProbe[1], Length(HelloProbe)),
    'zero-timeout read polls, then delivers the queued message');

  Cli.Close(1000, '');
  Check(Cli.ReadMessage(IsText, Data, 200) = wrrClosed,
    'bounded read after a clean close reports wrrClosed');
  Cli.Free;

  // --- permessage-deflate over the wire ----------------------------------
  Cli := TWSClient.Create;
  Cli.Connect(Url, True);
  Check(Cli.Deflate.Enabled, 'deflate negotiated when offered');
  S := '';
  for I := 1 to 8192 do
    S := S + 'compressible payload line ' + IntToStr(I and 7) + #10;
  Cli.SendText(S);
  Check(Cli.ReadMessage(IsText, Data) and IsText and
    (Length(Data) = Length(S)) and CompareMem(@Data[0], @S[1], Length(S)),
    'deflate echo ~200 KiB content-identical');
  Cli.Close;
  Cli.Free;

  // --- raw-socket violations ---------------------------------------------
  StressPhase := 'violation sections';
  // A client frame without a mask: MUST fail the connection, 1002 (§5.1).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  RawSendFrame(Fd, WS_OP_TEXT, 'naughty', False);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1002, 'unmasked client frame -> close 1002');

  // Close frame carrying reserved code 999: protocol error, 1002 (§7.4).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  RawSendFrame(Fd, WS_OP_CLOSE, Chr(999 shr 8) + Chr(999 and $FF), True);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1002, 'close with invalid code 999 -> close 1002');

  // Fragmented control frame (FIN=0 ping): 1002 (§5.5).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  S := #$09#$80; // FIN=0, opcode=9, masked, len 0
  S := S + #0#0#0#0; // mask key
  fpSend(Fd, @S[1], Length(S), 0);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1002, 'fragmented ping -> close 1002');

  // Text frame with invalid UTF-8: 1007 (§8.1).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  RawSendFrame(Fd, WS_OP_TEXT, #$FF#$FE'broken', True);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1007, 'invalid UTF-8 text -> close 1007');

  // --- plain HTTP on the WebSocket port (OnPlainRequest) ------------------
  // A second, short-lived server carries the hook: the fallback is
  // opt-in, so the main instance must stay hook-less for the refusal
  // check at the end of this section to mean anything.
  StressPhase := 'plain-request section';
  PlainHost := TPlainHost.Create;
  PlainSrvT := TServerThread.Create(True);
  PlainSrvT.Srv := TWSServer.Create(0, True);
  PlainSrvT.Srv.OnPlainRequest := PlainHost.Answer;
  PlainPort := PlainSrvT.Srv.Port;
  PlainSrvT.Start;

  // GET: the hook's bytes reach the wire verbatim, and the connection is
  // closed behind them — single-shot, no keep-alive.
  Fd := RawConnect(PlainPort);
  PlainReq := 'GET / HTTP/1.1'#13#10'Host: 127.0.0.1'#13#10#13#10;
  fpSend(Fd, @PlainReq[1], Length(PlainReq), 0);
  PlainGot := RawReadToEof(Fd, Eof);
  CloseSocket(Fd);
  Check((PlainGot = PlainResponse('GET', '/')) and Eof,
    'plain GET answered by the hook byte-for-byte, then EOF');

  // HEAD is eligible too (body-less by definition).
  Fd := RawConnect(PlainPort);
  PlainReq := 'HEAD /head HTTP/1.1'#13#10'Host: 127.0.0.1'#13#10#13#10;
  fpSend(Fd, @PlainReq[1], Length(PlainReq), 0);
  PlainGot := RawReadToEof(Fd, Eof);
  CloseSocket(Fd);
  Check((PlainGot = PlainResponse('HEAD', '/head')) and Eof,
    'plain HEAD reaches the hook');

  // A request advertising a body is never eligible, hook or no hook: the
  // standard refusal, and the hook is not consulted at all.
  PlainHost.Snapshot(PlainHitsBefore, PlainRaw);
  Fd := RawConnect(PlainPort);
  PlainReq := 'POST / HTTP/1.1'#13#10'Host: 127.0.0.1'#13#10 +
    'Content-Length: 0'#13#10#13#10;
  fpSend(Fd, @PlainReq[1], Length(PlainReq), 0);
  PlainGot := RawReadToEof(Fd, Eof);
  CloseSocket(Fd);
  PlainHost.Snapshot(PlainHits, PlainRaw);
  Check((Copy(PlainGot, 1, 12) = 'HTTP/1.1 400') and
    (PlainHits = PlainHitsBefore),
    'plain POST advertising a body refused 400, hook not consulted');

  // Two complete requests in one segment. Single-shot means exactly one
  // response and then EOF; the pipelined request is discarded, and the
  // hook is handed only the request block that completed — never the
  // bytes trailing it.
  PlainHost.Snapshot(PlainHitsBefore, PlainRaw);
  Fd := RawConnect(PlainPort);
  PlainReq := 'GET / HTTP/1.1'#13#10'Host: 127.0.0.1'#13#10#13#10 +
    'GET /second HTTP/1.1'#13#10'Host: 127.0.0.1'#13#10#13#10;
  fpSend(Fd, @PlainReq[1], Length(PlainReq), 0);
  PlainGot := RawReadToEof(Fd, Eof);
  CloseSocket(Fd);
  PlainHost.Snapshot(PlainHits, PlainRaw);
  Check((PlainGot = PlainResponse('GET', '/')) and Eof and
    (PlainHits = PlainHitsBefore + 1) and (Pos('/second', PlainRaw) = 0),
    'pipelined plain requests: one response, the second discarded');

  StressPhase := 'plain-request section: teardown';
  PlainSrvT.Terminate;
  PlainSrvT.Srv.Stop;
  PlainSrvT.WaitFor;
  PlainSrvT.Srv.Free;
  PlainSrvT.Free;
  PlainHost.Free;

  // Unset hook (the main server): the same request gets the refusal.
  Fd := RawConnect(Port);
  PlainReq := 'GET / HTTP/1.1'#13#10'Host: 127.0.0.1'#13#10#13#10;
  fpSend(Fd, @PlainReq[1], Length(PlainReq), 0);
  PlainGot := RawReadToEof(Fd, Eof);
  CloseSocket(Fd);
  Check(Copy(PlainGot, 1, 12) = 'HTTP/1.1 400',
    'plain GET refused 400 when no hook is set');

  // --- server TLS terminated by the transport (duetto#22) -----------------
  // Linux only: the epoll transport is what this section exercises, and
  // the macOS client rides SecureTransport, which will not trust a
  // runtime CA without keychain surgery. A third server carries it —
  // the flow-control watermarks are deliberately squeezed to lwpt's
  // floor here, which is not what a plaintext-adjacent listener wants.
  {$ifdef LINUX}
  StressPhase := 'tls section';
  TlsDir := IncludeTrailingPathDelimiter(GetTempDir) + 'duetto-interop-tls-' +
    IntToStr(FpGetPid) + PathDelim;
  if not TlsOpenSslPresent then
    WriteLn('skip - tls: openssl CLI not installed; wss section skipped')
  else if not TlsGenerateIdentity(TlsDir) then
    WriteLn('skip - tls: openssl could not build a test identity (see ',
      TlsDir, 'openssl.log); wss section skipped')
  else
  begin
    // Before the first client TLS use in this process: the client's
    // OpenSSL context loads its trust store once, at connect time.
    C_setenv('SSL_CERT_FILE', PAnsiChar(AnsiString(TlsDir + 'ca.crt')), 1);

    TlsCfg := WSTransportNoTls;
    TlsCfg.Enabled := True;
    TlsCfg.Pkcs12Path := TlsDir + 'identity.p12';
    TlsCfg.Pkcs12Passphrase := TlsPassphrase;
    TlsCfg.InputHighWater := TlsInputHighWater;
    TlsCfg.OutputCapacity := TlsOutputCapacity;
    TlsCfg.HandshakeDeadlineMs := TlsHandshakeDeadlineMs;
    TlsCfg.InboundHandshakeBudget := TlsInboundBudget;
    TlsSrvT := TServerThread.Create(True);
    TlsSrvT.Srv := TWSServer.Create(0, TlsCfg, True);
    TlsSrvT.Srv.OnMessage := Echo.OnMsg;
    TlsPort := TlsSrvT.Srv.Port;
    // The leaf carries 127.0.0.1 as a DNS SAN as well as an IP one, so
    // the client's hostname check passes without a name lookup — the
    // rest of the battery dials the loopback address for the same
    // reason.
    TlsUrl := Format('wss://127.0.0.1:%d/', [TlsPort]);
    TlsSrvT.Start;

    TlsCli := TWSClient.Create;
    TlsCli.Connect(TlsUrl);
    TlsCli.SendText(HelloProbe);
    Check(TlsCli.ReadMessage(IsText, Data) and IsText and
      (Length(Data) = Length(HelloProbe)) and
      CompareMem(@Data[0], @HelloProbe[1], Length(HelloProbe)),
      'tls: wss handshake and text echo');

    for I := 0 to 2 do
      TlsCli.SendText(PipelinedMsgs[I]);
    Ok := True;
    for I := 0 to 2 do
    begin
      S := PipelinedMsgs[I];
      Ok := Ok and TlsCli.ReadMessage(IsText, Data) and IsText and
        (Length(Data) = Length(S)) and CompareMem(@Data[0], @S[1], Length(S));
    end;
    Check(Ok, 'tls: three pipelined messages over wss, in order');

    // The flow-control proof. With the encrypted input window at
    // lwpt's floor, every 256 KB socket read is accepted a fraction at
    // a time and the remainder re-offered from the carry buffer; with
    // the output capacity at the floor, the echo is absorbed in ~30
    // capacity-sized bites re-offered through OnSendReady. Any byte
    // lost, duplicated or reordered on either side breaks the record
    // stream long before the payload compare.
    SetLength(Big, TlsBigEchoBytes);
    for I := 0 to High(Big) do
      Big[I] := Byte((I * 131 + 17) and $FF);
    TlsCli.SendBinary(@Big[0], Length(Big));
    Check(TlsCli.ReadMessage(IsText, Data) and (not IsText) and
      (Length(Data) = Length(Big)) and
      CompareMem(@Data[0], @Big[0], Length(Big)),
      Format('tls: %d KiB echo intact and in order through %d-byte ' +
      'input/output windows', [TlsBigEchoBytes div 1024, TlsInputHighWater]));

    TlsCli.Close(1000, 'done');
    Check(TlsCli.CloseCode = 1000, 'tls: clean close echoes 1000 over wss');
    TlsCli.Free;

    // close_notify before FIN, observed from a probe that keeps its
    // socket open past the WebSocket close: lwpt's blocking read
    // returns 0 on an orderly TLS shutdown and raises on a reset.
    StressPhase := 'tls section: close_notify probe';
    TlsProbeFd := RawConnectEx(TlsPort, False);
    StartTransportSecurity(TlsProbe, TlsProbeFd, '127.0.0.1');
    TlsOk := TlsProbe.Active;
    TlsLeft := TlsProbeHandshake(TlsProbe, TlsPort);
    TlsOk := TlsOk and TlsProbeWrite(TlsProbe,
      BuildFrameBytes(WS_OP_CLOSE, #$03#$E8, True));
    TlsCode := TlsProbeReadCloseCode(TlsProbe, TlsLeft);
    TlsOk := TlsOk and (TlsCode = 1000) and TlsProbeSawCloseNotify(TlsProbe);
    CloseTransportSecurity(TlsProbe);
    CloseSocket(TlsProbeFd);
    Check(TlsOk, 'tls: graceful close flushes close_notify before FIN');

    // A throttled peer. The probe's receive buffer is a fraction of the
    // echo it is about to earn, and it writes everything — one large
    // message plus a pipelined tail of small ones — before reading a
    // byte, so the server is holding several messages' worth of output
    // while more input keeps arriving. That is the transport's
    // re-offer accounting under maximum overlap; every message coming
    // back whole and in order is what says nothing was dropped,
    // duplicated or reordered.
    //
    // Neither write can wedge: the lead message is fully consumed
    // before its echo begins, and the tail is small enough to sit in
    // the socket buffers of a server that has stopped reading.
    StressPhase := 'tls section: throttled peer';
    TlsProbeFd := RawConnectEx(TlsPort, False, TlsBurstRecvBuf);
    StartTransportSecurity(TlsProbe, TlsProbeFd, '127.0.0.1');
    TlsLeft := TlsProbeHandshake(TlsProbe, TlsPort);
    SetLength(TlsSizes, TlsBurstTailCount + 1);
    TlsSizes[0] := TlsBurstLeadSize;
    for I := 1 to TlsBurstTailCount do
      TlsSizes[I] := TlsBurstTailSize;
    TlsOk := True;
    for I := 0 to TlsBurstTailCount do
    begin
      S := BuildFrameBytes(WS_OP_BINARY, TlsBurstPayload(I, TlsSizes[I]),
        True);
      TlsOk := TlsOk and TlsProbeWrite(TlsProbe, S);
    end;
    TlsOk := TlsOk and TlsProbeVerifyEchoes(TlsProbe, TlsLeft, TlsSizes);
    CloseTransportSecurity(TlsProbe);
    CloseSocket(TlsProbeFd);
    Check(TlsOk, Format('tls: %d KiB + %d x %d B pipelined behind a %d KiB ' +
      'receive window, every echo intact and in order',
      [TlsBurstLeadSize div 1024, TlsBurstTailCount, TlsBurstTailSize,
      TlsBurstRecvBuf div 1024]));

    // Slow loris: a plausible record header, then silence. Nothing in
    // the TLS engine can time this out — only the reactor's deadline.
    StressPhase := 'tls section: handshake deadline';
    Fd := RawConnect(TlsPort);
    S := #$16#$03#$01#$00#$C0;
    fpSend(Fd, @S[1], Length(S), TlsSendFlags);
    TlsElapsed := RawWaitForClose(Fd, TlsCloseBoundMs + 2000);
    CloseSocket(Fd);
    Check((TlsElapsed >= 0) and (TlsElapsed < TlsCloseBoundMs),
      Format('tls: silent peer dropped by the %d ms handshake deadline ' +
      '(after %d ms)', [TlsHandshakeDeadlineMs, TlsElapsed]));

    // Volume guard: far more ciphertext than any handshake needs, in
    // one burst. The connection dies bounded instead of buffering it.
    StressPhase := 'tls section: inbound budget';
    Fd := RawConnect(TlsPort);
    SetLength(Garbage, 256 * 1024);
    for I := 0 to High(Garbage) do
      Garbage[I] := Byte((I * 61 + 3) and $FF);
    fpSend(Fd, @Garbage[0], Length(Garbage), TlsSendFlags);
    TlsElapsed := RawWaitForClose(Fd, TlsCloseBoundMs + 2000);
    CloseSocket(Fd);
    Check((TlsElapsed >= 0) and (TlsElapsed < TlsCloseBoundMs),
      Format('tls: %d KiB pre-handshake flood dropped against a %d KiB ' +
      'budget (after %d ms)', [Length(Garbage) div 1024,
      TlsInboundBudget div 1024, TlsElapsed]));

    // Both guards fire per connection, not per listener.
    StressPhase := 'tls section: survivor';
    TlsCli := TWSClient.Create;
    TlsCli.Connect(TlsUrl);
    TlsCli.SendText(HelloProbe);
    Ok := TlsCli.ReadMessage(IsText, Data) and IsText and
      (Length(Data) = Length(HelloProbe));
    TlsCli.Close(1000, '');
    TlsCli.Free;
    Check(Ok, 'tls: the listener still serves wss after both guards fired');

    StressPhase := 'tls section: teardown';
    TlsSrvT.Terminate;
    TlsSrvT.Srv.Stop;
    TlsSrvT.WaitFor;
    TlsSrvT.Srv.Free;
    TlsSrvT.Free;
    try
      ExecuteProcess('/bin/sh', ['-c', 'rm -rf "' + TlsDir + '"']);
    except
      // A leftover temp directory is not a battery failure.
    end;
  end;
  {$else}
  WriteLn('skip - tls: the wss section is Linux-only (it exercises the ',
    'epoll transport; macOS server TLS is Network.framework and the ',
    'macOS client cannot trust a runtime CA)');
  {$endif}

  // --- concurrent-connections stress -------------------------------------
  StressPhase := 'storm';
  // The budget is a floor under the window in which all 33 threads are
  // live, so it is taken after the last Start below — not here, where a
  // worker scheduled 200 ms late would find its budget already spent and
  // record zero cycles. Seeded now only so the value is never garbage.
  Deadline := GetTickCount64 + StressBudgetMs;
  LiveEcho := StressEchoWorkerCount;
  for I := 0 to High(EchoWorkers) do
  begin
    EchoWorkers[I] := TStressEchoWorker.Create(True);
    EchoWorkers[I].Seed := I;
    EchoWorkers[I].Url := Url;
    EchoWorkers[I].DeadlinePtr := @Deadline;
    EchoWorkers[I].LiveEchoPtr := @LiveEcho;
  end;
  for I := 0 to High(DropWorkers) do
  begin
    DropWorkers[I] := TStressDropWorker.Create(True);
    DropWorkers[I].Seed := I;
    DropWorkers[I].Port := Port;
    DropWorkers[I].DeadlinePtr := @Deadline;
    DropWorkers[I].LiveEchoPtr := @LiveEcho;
  end;
  Pusher := TStressPusher.Create(True);
  Pusher.Tracker := Tracker;
  Pusher.DeadlinePtr := @Deadline;
  Pusher.LiveEchoPtr := @LiveEcho;

  for I := 0 to High(EchoWorkers) do
    EchoWorkers[I].Start;
  for I := 0 to High(DropWorkers) do
    DropWorkers[I].Start;
  Pusher.Start;
  // Every thread now exists; start the clock they all read.
  Deadline := GetTickCount64 + StressBudgetMs;

  for I := 0 to High(EchoWorkers) do
    EchoWorkers[I].WaitFor;
  for I := 0 to High(DropWorkers) do
    DropWorkers[I].WaitFor;
  Pusher.Terminate;
  Pusher.WaitFor; // no Post may race the server teardown below

  AllOk := True;
  PushAllOk := True;
  TotalCycles := 0;
  TotalPushes := 0;
  for I := 0 to High(EchoWorkers) do
  begin
    // Every worker completes a cycle unless it never ran at all — say so
    // rather than failing the line with an empty diagnostic.
    if EchoWorkers[I].Cycles = 0 then
      EchoWorkers[I].MarkFailed('worker completed no cycles');
    AllOk := AllOk and EchoWorkers[I].Ok;
    PushAllOk := PushAllOk and EchoWorkers[I].PushOk;
    Inc(TotalCycles, EchoWorkers[I].Cycles);
    Inc(TotalPushes, EchoWorkers[I].Pushes);
  end;
  Check(AllOk, Format(
    'stress: %d echo workers, %d cycles, echoes intact and in order',
    [StressEchoWorkerCount, TotalCycles]));
  for I := 0 to High(EchoWorkers) do
    if not EchoWorkers[I].Ok then
      WriteLn('       echo worker ', I, ': ', EchoWorkers[I].FailMsg);

  // Push correctness is the push check's business: a serial violation
  // shows up here, not folded into the echo line above.
  Check(PushAllOk and (TotalPushes > 0), Format(
    'stress: %d pushes interleaved, serials consecutive per connection',
    [TotalPushes]));
  for I := 0 to High(EchoWorkers) do
    if not EchoWorkers[I].PushOk then
      WriteLn('       echo worker ', I, ' push stream: ',
        EchoWorkers[I].PushFailMsg);
  if not Pusher.Ok then
    WriteLn('       pusher thread: ', Pusher.FailMsg);
  if Pusher.FatalException <> nil then
    WriteLn('       pusher thread died: ',
      Exception(Pusher.FatalException).Message);
  Check(Pusher.Ok and (Pusher.FatalException = nil),
    'stress: pusher thread survived the storm');

  AllOk := True;
  TotalDrops := 0;
  TotalTransient := 0;
  for I := 0 to High(DropWorkers) do
  begin
    if DropWorkers[I].Cycles = 0 then
      DropWorkers[I].MarkFailed('worker completed no cycles');
    AllOk := AllOk and DropWorkers[I].Ok;
    Inc(TotalDrops, DropWorkers[I].Cycles);
    Inc(TotalTransient, DropWorkers[I].TransientTotal);
  end;
  // Transient failures are reported, not asserted on: loopback churn
  // makes the odd connect or handshake read fail, and only a consecutive
  // streak (the 5-in-a-row rule in the worker) fails the battery.
  Check(AllOk, Format(
    'stress: %d abrupt drops absorbed mid-traffic (%d transient retries)',
    [TotalDrops, TotalTransient]));
  for I := 0 to High(DropWorkers) do
    if not DropWorkers[I].Ok then
      WriteLn('       drop worker ', I, ': ', DropWorkers[I].FailMsg);

  for I := 0 to High(EchoWorkers) do
    EchoWorkers[I].Free;
  for I := 0 to High(DropWorkers) do
    DropWorkers[I].Free;
  Pusher.Free;

  // Prove the server is still healthy after the storm, then leave the
  // connections open so the teardown below is a Shutdown with live
  // connections — the drain must complete and the process exit cleanly.
  StressPhase := 'storm joined; workers freed';
  LingerVerified := 0;
  LingerBad := '';
  // Local class-reference array: FPC does not zero it, and the except
  // arm below survives a partial fill — the nil guards on the read and
  // free loops need real nils, not stack garbage.
  FillChar(Linger, SizeOf(Linger), 0);
  // Runs on the main thread, so a connect that exhausts its retries
  // would abort the process before the summary; catch it and turn it
  // into the failure this check exists to report.
  try
    for I := 0 to High(Linger) do
    begin
      StressPhase := 'linger connect ' + IntToStr(I);
      Linger[I] := StressConnect(Url);
      StressPhase := 'linger send ' + IntToStr(I);
      Linger[I].SendText(LingerProbe);
    end;
    // Every connection is read and judged on its own: a short-circuit
    // would leave the later reads unrun while claiming all of them.
    for I := 0 to High(Linger) do
    begin
      StressPhase := 'linger read ' + IntToStr(I);
      LingerOk[I] := (Linger[I].ReadMessage(IsText, Data,
        StressStallLimitMs) = wrrMessage) and IsText and
        (Length(Data) = Length(LingerProbe)) and
        CompareMem(@Data[0], @LingerProbe[1], Length(LingerProbe));
      if LingerOk[I] then
        Inc(LingerVerified)
      else
        LingerBad := LingerBad + ' ' + IntToStr(I);
    end;
    if LingerBad <> '' then
      WriteLn('       linger connections that did not echo:', LingerBad);
    Check(LingerVerified = StressLingerCount, Format(
      'stress: server healthy after the storm, %d/%d connections echoed ' +
      'and held open', [LingerVerified, StressLingerCount]));
  except
    on E: Exception do
      Check(False, 'stress: server healthy after the storm (' +
        E.Message + ')');
  end;

  StressPhase := 'teardown: stop + waitfor';
  SrvT.Terminate;
  SrvT.Srv.Stop;
  SrvT.WaitFor;
  // A transport exception (e.g. a fatal ArmAccept error) unwinds Run
  // and lands here, not in a crash — surface it instead of letting a
  // dead server thread masquerade as a mystery wedge.
  if SrvT.FatalException <> nil then
    WriteLn('       server thread died: ',
      Exception(SrvT.FatalException).Message);
  Check(SrvT.FatalException = nil, 'stress: server thread survived the storm');
  // TWSServer.Destroy tears its registry down without firing
  // OnClientClose, so the tracker would keep pointers to connections the
  // free below reclaims. Drop them while they are still valid.
  Tracker.Clear;
  StressPhase := 'teardown: server free (shutdown drain)';
  SrvT.Srv.Free; // Shutdown quiesces and drains with the linger conns open
  SrvT.Free;
  // The drain is only "clean" if the peers actually saw it: Destroy
  // frees registry connections without a closing handshake, so each
  // linger client should observe abrupt closure — wrrClosed, with no
  // close code to assert.
  Ok := True;
  for I := 0 to High(Linger) do
  begin
    StressPhase := 'teardown: linger closure ' + IntToStr(I);
    Ok := Ok and (Linger[I] <> nil) and
      (Linger[I].ReadMessage(IsText, Data, StressStallLimitMs) = wrrClosed);
  end;
  Check(Ok, Format('stress: shutdown with %d live connections drained ' +
    'cleanly, every peer saw the close', [StressLingerCount]));
  StressDone := True;
  Watchdog.WaitFor; // exits within one 250 ms poll slice
  Watchdog.Free;

  for I := 0 to High(Linger) do
    if Linger[I] <> nil then Linger[I].Free;
  Tracker.Free;
  Echo.Free;

  WriteLn;
  if Failures = 0 then
    WriteLn('interop: ALL CHECKS PASSED')
  else
    WriteLn('interop: ', Failures, ' FAILURE(S)');
  Halt(Ord(Failures > 0));
end.
