program wsinterop;

// Live-socket battery: duetto TWSClient against duetto TWSServer over real
// TCP (loopback), plus a raw-socket section that injects protocol
// violations a conforming client cannot produce and asserts the close
// codes RFC 6455 (and Autobahn cases 4.x/7.x) require, and an
// upgrade-hook section: a second server bound to 127.0.0.1 explicitly
// whose OnUpgradeRequest vetoes one Origin (403 + close, no OnOpen) and
// whose raising-hook mode is treated the same way.
//
// Exit 0 = every check passed.

{$I Shared.inc}

uses
  {$ifdef UNIX} cthreads, {$endif}
  syncobjs,
  SysUtils, Classes, Sockets,
  WS.Server, WS.Client, WS.Frame, WS.Handshake;

type
  {$ifdef UNIX}
  TInteropTimeVal = record
    Seconds: PtrInt;
    Microseconds: PtrInt;
  end;
  {$endif}

  TEcho = class
    procedure OnMsg(AConn: TWSConnection; AText: Boolean; P: PByte; Len: NativeInt);
  end;

  // OnUpgradeRequest host for the hook section: refuses one Origin with
  // a reason, raises instead when told to, and counts what the server
  // went on to do — a refused handshake must produce neither OnOpen nor
  // OnClientClose. Runs on the connection's execution context, hence
  // the lock around the counters the battery reads.
  TUpgradeGate = class
  private
    FLock: TCriticalSection;
    FHits, FOpens, FCloses: Integer;
    FRaiseMode: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    function Check(const AHS: TWSServerHandshake;
      const ARawRequest: RawByteString; out AReason: string): Boolean;
    procedure HandleOpen(AConn: TWSConnection);
    procedure HandleClose(AConn: TWSConnection);
    procedure SetRaiseMode(AValue: Boolean);
    procedure Snapshot(out AHits, AOpens, ACloses: Integer);
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

{ TUpgradeGate }

const
  ForbiddenOrigin = 'http://evil.example';
  ForbiddenReason = 'origin not allowed';

constructor TUpgradeGate.Create;
begin
  inherited;
  FLock := TCriticalSection.Create;
end;

destructor TUpgradeGate.Destroy;
begin
  FLock.Free;
  inherited;
end;

function TUpgradeGate.Check(const AHS: TWSServerHandshake;
  const ARawRequest: RawByteString; out AReason: string): Boolean;
var
  RaiseNow: Boolean;
begin
  FLock.Acquire;
  try
    Inc(FHits);
    RaiseNow := FRaiseMode;
  finally
    FLock.Release;
  end;
  if RaiseNow then
    raise Exception.Create('hook exploded on purpose');
  // The parsed Origin and the raw block must agree — the hook is
  // promised exactly this request's headers.
  Result := (AHS.Origin <> ForbiddenOrigin) and
    (HeaderValue(ARawRequest, 'Origin') = AHS.Origin);
  if not Result then AReason := ForbiddenReason;
end;

procedure TUpgradeGate.HandleOpen(AConn: TWSConnection);
begin
  FLock.Acquire;
  try
    Inc(FOpens);
  finally
    FLock.Release;
  end;
end;

procedure TUpgradeGate.HandleClose(AConn: TWSConnection);
begin
  FLock.Acquire;
  try
    Inc(FCloses);
  finally
    FLock.Release;
  end;
end;

procedure TUpgradeGate.SetRaiseMode(AValue: Boolean);
begin
  FLock.Acquire;
  try
    FRaiseMode := AValue;
  finally
    FLock.Release;
  end;
end;

procedure TUpgradeGate.Snapshot(out AHits, AOpens, ACloses: Integer);
begin
  FLock.Acquire;
  try
    AHits := FHits;
    AOpens := FOpens;
    ACloses := FCloses;
  finally
    FLock.Release;
  end;
end;

procedure TServerThread.Execute;
begin
  while not Terminated do
    Srv.Run(50);
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

function RawConnect(APort: Word): Tsocket;
var
  SA: TInetSockAddr;
  {$ifdef WINDOWS}
  TimeoutMs: Cardinal;
  {$else}
  TV: TInteropTimeVal;
  {$endif}
begin
  Result := fpSocket(AF_INET, SOCK_STREAM, 0);
  {$ifdef WINDOWS}
  TimeoutMs := 5000;
  fpSetSockOpt(Result, SOL_SOCKET, SO_RCVTIMEO, @TimeoutMs,
    SizeOf(TimeoutMs));
  {$else}
  TV.Seconds := 5; TV.Microseconds := 0;
  fpSetSockOpt(Result, SOL_SOCKET, SO_RCVTIMEO, @TV, SizeOf(TV));
  {$endif}
  FillChar(SA, SizeOf(SA), 0);
  SA.sin_family := AF_INET;
  SA.sin_port := htons(APort);
  SA.sin_addr.s_addr := htonl($7F000001); // 127.0.0.1
  if fpConnect(Result, @SA, SizeOf(SA)) <> 0 then
    raise Exception.Create('raw connect failed');
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

// Send an upgrade request carrying AExtraHeaders (complete CRLF-terminated
// lines, or '') and return the response header block — whatever status
// it carries. AEof reports whether the server closed the socket behind
// it (read until EOF once the block is complete; a 101 leaves the socket
// open, so that read is only attempted when the status is not 101).
function RawUpgrade(AFd: Tsocket; const AExtraHeaders: RawByteString;
  out AEof: Boolean): RawByteString;
var
  Req: RawByteString;
  Buf: array[0..4095] of Byte;
  Got, HdrEnd: Integer;
begin
  Req := ClientBuildRequest('127.0.0.1', '/', ClientGenerateKey, False);
  // Splice the extra lines in ahead of the terminating blank line.
  Insert(AExtraHeaders, Req, Length(Req) - 1);
  fpSend(AFd, @Req[1], Length(Req), 0);
  Result := '';
  AEof := False;
  repeat
    Got := fpRecv(AFd, @Buf[0], SizeOf(Buf), 0);
    if Got <= 0 then Exit;
    SetLength(Result, Length(Result) + Got);
    Move(Buf[0], Result[Length(Result) - Got + 1], Got);
    HdrEnd := HandshakeFindEnd(Result);
  until HdrEnd > 0;
  if Pos(' 101 ', Copy(Result, 1, 16)) > 0 then Exit;
  repeat
    Got := fpRecv(AFd, @Buf[0], SizeOf(Buf), 0);
    if Got <= 0 then Break;
    SetLength(Result, Length(Result) + Got);
    Move(Buf[0], Result[Length(Result) - Got + 1], Got);
  until False;
  AEof := Got = 0;
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

procedure RawSendFrame(AFd: Tsocket; AOpcode: Byte; const APayload: RawByteString;
  AMasked: Boolean);
var
  Hdr: array[0..WS_MAX_HEADER - 1] of Byte;
  HLen: Integer;
  Key: UInt32;
  Body: TBytes;
begin
  Key := $A1B2C3D4;
  HLen := WriteFrameHeader(@Hdr[0], True, False, AOpcode, AMasked, Key,
    Length(APayload));
  fpSend(AFd, @Hdr[0], HLen, 0);
  if APayload = '' then Exit;
  SetLength(Body, Length(APayload));
  Move(APayload[1], Body[0], Length(APayload));
  if AMasked then
    ApplyMask(PByte(Body), Length(Body), Key, 0);
  fpSend(AFd, @Body[0], Length(Body), 0);
end;

// ---------------------------------------------------------------------------

const
  HelloProbe: RawByteString = 'hello duetto';
  PipelinedMsgs: array[0..2] of RawByteString = ('one', 'two', 'three');

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
  // Upgrade-hook section
  Gate: TUpgradeGate;
  HookSrvT: TServerThread;
  HookPort: Word;
  Resp: RawByteString;
  Eof: Boolean;
  Hits, Opens, Closes: Integer;
begin
  Echo := TEcho.Create;
  SrvT := TServerThread.Create(True);
  SrvT.Srv := TWSServer.Create(0, True); // port 0 = kernel-assigned
  SrvT.Srv.OnMessage := Echo.OnMsg;
  Port := SrvT.Srv.Port;
  Url := Format('ws://127.0.0.1:%d/', [Port]);
  SrvT.Start;
  WriteLn('server on ', Port);
  Flush(Output);
  LastTick := GetTickCount64;

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

  // --- bind address + OnUpgradeRequest -----------------------------------
  // A second server, bound to 127.0.0.1 explicitly (port 0 still
  // kernel-assigned) and carrying the veto hook; the main instance stays
  // hook-less so the sections above keep meaning "accept everything".
  Gate := TUpgradeGate.Create;
  HookSrvT := TServerThread.Create(True);
  HookSrvT.Srv := TWSServer.Create(0, True, 16 * 1024 * 1024, '127.0.0.1');
  HookSrvT.Srv.OnMessage := Echo.OnMsg;
  HookSrvT.Srv.OnOpen := Gate.HandleOpen;
  HookSrvT.Srv.OnClientClose := Gate.HandleClose;
  HookSrvT.Srv.OnUpgradeRequest := Gate.Check;
  HookPort := HookSrvT.Srv.Port;
  HookSrvT.Start;
  Check(HookPort <> 0, 'server bound to 127.0.0.1 resolves its port');

  // Refusals first, while no connection has ever been opened on this
  // server: afterwards the open/close counters must still read zero.
  Fd := RawConnect(HookPort);
  Resp := RawUpgrade(Fd, 'Origin: ' + ForbiddenOrigin + #13#10, Eof);
  CloseSocket(Fd);
  Check((Copy(Resp, 1, 22) = 'HTTP/1.1 403 Forbidden') and Eof and
    (Pos(#13#10#13#10 + ForbiddenReason, Resp) > 0),
    'forbidden Origin -> 403 with the hook''s reason, then EOF');

  Gate.SetRaiseMode(True);
  Fd := RawConnect(HookPort);
  Resp := RawUpgrade(Fd, '', Eof);
  CloseSocket(Fd);
  Gate.SetRaiseMode(False);
  Check((Copy(Resp, 1, 22) = 'HTTP/1.1 403 Forbidden') and Eof and
    (Pos(#13#10#13#10'forbidden', Resp) > 0),
    'raising hook -> 403 ''forbidden'', then EOF');

  Gate.Snapshot(Hits, Opens, Closes);
  Check((Hits = 2) and (Opens = 0) and (Closes = 0),
    'refused handshakes: hook consulted, no OnOpen, no OnClientClose');

  // No Origin at all (a non-browser client): accepted, and the
  // connection is a normal one — echo proves OnOpen ran ahead of it.
  Cli := TWSClient.Create;
  Cli.Connect(Format('ws://127.0.0.1:%d/', [HookPort]));
  Cli.SendText(HelloProbe);
  Check(Cli.ReadMessage(IsText, Data) and IsText and
    (Length(Data) = Length(HelloProbe)) and
    CompareMem(@Data[0], @HelloProbe[1], Length(HelloProbe)),
    'loopback-bound server: client handshake without Origin -> 101, echo');
  Cli.Close(1000, 'done');
  Cli.Free;

  // An allowed Origin: 101, and the socket stays open for frames.
  Fd := RawConnect(HookPort);
  Resp := RawUpgrade(Fd, 'Origin: http://good.example'#13#10, Eof);
  Ok := Pos(' 101 ', Copy(Resp, 1, 16)) > 0;
  if Ok then
  begin
    RawSendFrame(Fd, WS_OP_TEXT, 'still here', True);
    RawSendFrame(Fd, WS_OP_CLOSE, #$03#$E8, True); // 1000
    Ok := RawReadCloseCode(Fd, nil) = 1000;
  end;
  CloseSocket(Fd);
  Check(Ok, 'allowed Origin -> 101, frames flow, clean close');

  Gate.Snapshot(Hits, Opens, Closes);
  Check((Hits = 4) and (Opens = 2),
    'accepted handshakes: hook consulted, OnOpen fired for each');

  HookSrvT.Terminate;
  HookSrvT.Srv.Stop;
  HookSrvT.WaitFor;
  HookSrvT.Srv.Free;
  HookSrvT.Free;
  Gate.Free;

  SrvT.Terminate;
  SrvT.Srv.Stop;
  SrvT.WaitFor;
  SrvT.Srv.Free;
  SrvT.Free;
  Echo.Free;

  WriteLn;
  if Failures = 0 then
    WriteLn('interop: ALL CHECKS PASSED')
  else
    WriteLn('interop: ', Failures, ' FAILURE(S)');
  Halt(Ord(Failures > 0));
end.
