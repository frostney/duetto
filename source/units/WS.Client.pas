unit WS.Client;

// Blocking RFC 6455 client. ws:// is raw TCP; wss:// rides lwpt's
// TransportSecurity (OpenSSL on Linux, SecureTransport on macOS, Schannel
// on Windows — same backend the lwpt HTTP client trusts).
//
// All protocol behaviour lives in TWSProtocol; this unit is the socket,
// the TLS shim, the opening handshake, and a pump loop. ReadMessage blocks
// until a complete message arrives (pings are answered invisibly along the
// way) or the connection ends; a bounded overload caps the wait instead.
// An optional OnMessage handler takes delivery synchronously, inside the
// read, for applications that must answer a message before anything
// later in the same read is acted on.
//
// Failure contract: a dead peer, a reset, a failed send or a TLS error
// never raises out of a send, a read or Close. It ends the connection
// (Open goes False), and the next ReadMessage reports it (False /
// wrrClosed, CloseCode 1006 unless a close frame arrived). Connect is the
// one call that raises, always EWSClient, TLS failures included.
//
// SIGPIPE: plaintext sends carry MSG_NOSIGNAL on Linux, and Darwin
// sockets set SO_NOSIGPIPE, which also covers lwpt's SecureTransport
// writes. On Linux, wss:// writes go through OpenSSL's own socket BIO,
// which this unit cannot flag: a write into a reset TLS connection (the
// close_notify a teardown sends included) can still raise SIGPIPE there
// until lwpt sends with MSG_NOSIGNAL (duetto#79). A Linux process using
// wss:// should ignore SIGPIPE until then.

{$I Shared.inc}

interface

uses
  SysUtils,
  {$ifdef UNIX}
  BaseUnix, Sockets, netdb,
  {$endif}
  {$ifdef WINDOWS}
  WinSock2,
  {$endif}
  TransportSecurity,
  WS.Clock, WS.Handshake, WS.Protocol;

type
  EWSClient = class(Exception);

  TWSPlatformSocket = Tsocket;

const
  {$ifdef WINDOWS}
  WSSocketInvalid = INVALID_SOCKET;
  {$else}
  WSSocketInvalid = TWSPlatformSocket(-1);
  {$endif}

  // TWSClient's timeout defaults, in milliseconds. See the properties.
  WSDefaultConnectTimeoutMs = 10000;
  WSDefaultHandshakeTimeoutMs = 10000;
  WSDefaultCloseTimeoutMs = 5000;

type
  // Outcome of the bounded ReadMessage overload.
  TWSReadResult = (wrrMessage, wrrTimeout, wrrClosed);

  // A pointer-to-bytes view wide enough that an open-array parameter
  // sees the caller's length, never its own: lwpt's TransportSecurityRead
  // clamps to Length(ABuffer), and a dereferenced PByte is an open array
  // of exactly one element.
  TWSByteSpan = array[0..MaxInt - 1] of Byte;
  PWSByteSpan = ^TWSByteSpan;

  TWSClient = class;

  // P/Len are valid only for the duration of the callback: they may point
  // into the client's read buffer, overwritten by the next read. Copy the
  // bytes to keep them.
  TWSClientMessage = procedure(AClient: TWSClient; AText: Boolean;
    P: PByte; Len: NativeInt) of object;

  TWSClient = class
  private
    FSock: TWSPlatformSocket;
    FTls: TTransportSecurityConnection;
    FUseTls: Boolean;
    FProto: TWSProtocol;
    FOpen: Boolean;
    FDeflate: TWSDeflateParams;
    FOnMessage: TWSClientMessage;
    FDelivering: Boolean; // inside OnMessage, i.e. inside FProto.Ingest
    FConnectTimeoutMs: Integer;
    FHandshakeTimeoutMs: Integer;
    FCloseTimeoutMs: Integer;
    FTlsError: string; // the last TLS failure, for Connect's message

    // pending complete messages (several can arrive in one TCP read)
    FQueue: array of record Text: Boolean; Data: TBytes; end;
    FQHead, FQTail: Integer;

    FRecvBuf: TBytes;

    procedure ProtoMessage(AText: Boolean; P: PByte; ALen: NativeInt);
    function RawRead(P: PByte; ALen: Integer): Integer;
    function RawWrite(P: PByte; ALen: Integer): Integer;
    function TlsRead(P: PByte; ALen: Integer): Integer;
    function TlsWrite(P: PByte; ALen: Integer): Integer;
    procedure FlushOut;
    function PumpOnce: Boolean;
    function WaitReadable(ATimeoutMs: Integer): Boolean;
    procedure PopMessage(out AText: Boolean; out AData: TBytes); inline;
    procedure RefuseReadInHandler; inline;
    procedure ReleaseTransport;
    procedure ResetConnection;
    procedure StartTls(const AHost: string);
    function ReadUpgradeResponse(ADeadline: QWord; out AHeaderEnd: Integer;
      const APeer: string): RawByteString;
    procedure AwaitCloseEcho;
  public
    constructor Create;
    destructor Destroy; override;

    // url: ws://host[:port]/path or wss://host[:port]/path
    //
    // Raises EWSClient on any failure — resolution, connect, TLS, a
    // timeout or a rejected upgrade — and leaves no socket or TLS
    // session behind. A client is reusable: Connect after Close, after a
    // failed Connect or after a connection ended by itself (a dead peer,
    // a raising OnMessage) first releases everything the previous
    // connection held, its undrained ReadMessage queue included. Until
    // then that queue stays readable, so messages that arrived before a
    // close are not lost to it. Connect on an open client raises.
    procedure Connect(const AUrl: string; AOfferDeflate: Boolean = False;
      AMaxMessage: NativeInt = WS_DEFAULT_MAX_MESSAGE);

    procedure SendText(const S: RawByteString);
    procedure SendBinary(P: PByte; ALen: NativeInt);
    procedure Ping(const S: RawByteString = '');

    // Blocks until a message arrives. False = connection closed (see
    // CloseCode/CloseReason) or failed.
    function ReadMessage(out AText: Boolean; out AData: TBytes): Boolean;
      overload;

    // Bounded variant. Waits at most ATimeoutMs milliseconds for a
    // complete message. A message already queued returns immediately,
    // without a clock read or a poll. ATimeoutMs <= 0 means a single
    // non-blocking round: take whatever the socket already holds, never
    // block. wrrClosed covers clean close and failure alike — inspect
    // CloseCode afterwards, exactly like the unbounded form's False.
    //
    // What the bound is worth:
    //
    // Over ws:// the deadline bounds total wall clock — every blocking
    // step is a readiness poll sized by the remainder, so a peer
    // trickling a partial frame cannot stretch the wait.
    //
    // Over wss:// the deadline bounds waiting for ciphertext to arrive.
    // Once a TLS record has begun arriving the read blocks until that
    // record completes, and plaintext the TLS layer has decrypted but
    // not yet handed over is invisible to a readiness poll on the raw
    // socket: a complete message can sit inside the TLS layer while
    // this call reports wrrTimeout. lwpt's TransportSecurity exposes no
    // pending-plaintext query to close that gap yet.
    //
    // The deadline comes from WSMonotonicMs, so a wall-clock step
    // during the wait neither shortens nor extends it.
    //
    // Control replies owed to the peer (a pong for a ping that arrived
    // mid-wait) are flushed on a blocking socket, so peer backpressure
    // can push the call briefly past the bound.
    function ReadMessage(out AText: Boolean; out AData: TBytes;
      ATimeoutMs: Integer): TWSReadResult; overload;

    // Initiate the closing handshake, wait at most CloseTimeoutMs for the
    // echo, then drop TCP regardless. Never raises on a dead connection.
    procedure Close(ACode: Word = 1000; const AReason: string = '');

    // Optional synchronous delivery, the client's counterpart of the
    // server's OnMessage. When assigned, each complete message goes to
    // the handler from inside the read that completed it, instead of to
    // the ReadMessage queue, and the rest of that read waits until the
    // handler returns. A send made here therefore leaves ahead of
    // anything later in the same read provokes: when a valid message
    // and a frame that fails the connection arrive together, the reply
    // goes out before the failure's close frame. Assign it before
    // Connect so messages pipelined behind the 101 take this path too.
    //
    // SendText, SendBinary and Ping work from inside the handler. Close
    // there only sends the close frame; the echo is awaited by the reads
    // that follow, or by a later Close, which waits for it (bounded) as
    // usual. Either ReadMessage raises EWSClient there (the read in
    // progress cannot be re-entered). An exception escaping the handler
    // propagates out of the call that was reading (ReadMessage, Connect
    // or Close) and ends the connection: the rest of that read is lost.
    //
    // With a handler assigned, ReadMessage is the pump that drives it:
    // the unbounded form returns False once the connection has ended;
    // the bounded form returns wrrTimeout or wrrClosed. Messages queued
    // before the handler was assigned are still returned by ReadMessage.
    property OnMessage: TWSClientMessage read FOnMessage write FOnMessage;

    // Timeouts, in milliseconds, read by the next Connect or Close. Every
    // bound runs on WSMonotonicMs, so a wall-clock step cannot move it.
    //
    // ConnectTimeoutMs (default 10 s) bounds the TCP connect, shared by
    // every address a name resolves to. Name resolution itself is not
    // bounded. <= 0 waits as long as the OS keeps trying (minutes on
    // Linux against a host that drops SYNs).
    //
    // HandshakeTimeoutMs (default 10 s) starts once TCP is connected and
    // bounds the opening handshake: sending the upgrade request and
    // waiting for the 101. <= 0 waits indefinitely. Over wss:// it is
    // weaker. The TLS handshake counts against the budget but is not cut
    // short by it: lwpt's TransportSecurity keeps a handshake deadline
    // armed for the life of the session, so a long-lived connection would
    // fail once it had passed, and the TLS handshake runs without one
    // until lwpt can disarm it. The wait for the 101 is then bounded only
    // until TLS bytes arrive, as in the bounded ReadMessage: once a
    // record starts arriving the read blocks until an application record
    // completes. A server that stalls inside TLS is not bounded.
    //
    // CloseTimeoutMs (default 5 s) bounds Close's wait for the peer's
    // close echo; TCP is dropped when it runs out. <= 0 skips the wait:
    // the close frame is sent and the connection dropped at once. The
    // wait covers arriving bytes only, with the same wss:// caveat as the
    // bounded ReadMessage, and a close frame queued behind a peer that
    // has stopped reading is sent on a blocking socket.
    property ConnectTimeoutMs: Integer read FConnectTimeoutMs
      write FConnectTimeoutMs;
    property HandshakeTimeoutMs: Integer read FHandshakeTimeoutMs
      write FHandshakeTimeoutMs;
    property CloseTimeoutMs: Integer read FCloseTimeoutMs
      write FCloseTimeoutMs;

    property Open: Boolean read FOpen;
    property Deflate: TWSDeflateParams read FDeflate;
    function CloseCode: Word;
    function CloseReason: string;
  end;

implementation

{ url parsing — deliberately minimal: scheme://host[:port]path }

procedure ParseWsUrl(const AUrl: string; out ATls: Boolean;
  out AHost: string; out APort: Integer; out APath: string);
var
  Rest: string;
  Slash, Colon: Integer;
begin
  if Copy(AUrl, 1, 5) = 'ws://' then
  begin
    ATls := False;
    Rest := Copy(AUrl, 6, MaxInt);
    APort := 80;
  end
  else if Copy(AUrl, 1, 6) = 'wss://' then
  begin
    ATls := True;
    Rest := Copy(AUrl, 7, MaxInt);
    APort := 443;
  end
  else
    raise EWSClient.Create('URL must start with ws:// or wss://');

  Slash := Pos('/', Rest);
  if Slash = 0 then
  begin
    APath := '/';
  end
  else
  begin
    APath := Copy(Rest, Slash, MaxInt);
    Rest := Copy(Rest, 1, Slash - 1);
  end;

  Colon := Pos(':', Rest);
  if Colon > 0 then
  begin
    APort := StrToIntDef(Copy(Rest, Colon + 1, MaxInt), -1);
    if APort <= 0 then raise EWSClient.Create('bad port in URL');
    AHost := Copy(Rest, 1, Colon - 1);
  end
  else
    AHost := Rest;

  if AHost = '' then raise EWSClient.Create('missing host in URL');
end;

{ sockets }

const
  {$ifdef LINUX}
  // A send into a reset connection fails with EPIPE instead of raising
  // SIGPIPE, which would kill the host process.
  WSSendFlags = MSG_NOSIGNAL;
  {$else}
  WSSendFlags = 0;
  {$endif}
  {$ifdef DARWIN}
  // <sys/socket.h>. Darwin has no MSG_NOSIGNAL; set on the socket, it
  // covers every send through it, lwpt's SecureTransport writes included.
  WSSoNoSigPipe = $1022;
  {$endif}
  WSNoDeadline = 0;

// The deadline for a timeout property: WSNoDeadline when ATimeoutMs <= 0.
function DeadlineAfter(ATimeoutMs: Integer): QWord;
begin
  if ATimeoutMs <= 0 then Exit(WSNoDeadline);
  Result := WSMonotonicMs + QWord(ATimeoutMs);
end;

// Milliseconds left before ADeadline: -1 (wait without limit) for
// WSNoDeadline, 0 once it has passed.
function RemainingMs(ADeadline: QWord): Integer;
var
  Left: Int64;
begin
  if ADeadline = WSNoDeadline then Exit(-1);
  Left := Int64(ADeadline) - Int64(WSMonotonicMs);
  if Left <= 0 then Exit(0);
  if Left > High(Integer) then Exit(High(Integer));
  Result := Integer(Left);
end;

procedure CloseSocketHandle(ASock: TWSPlatformSocket);
begin
  {$ifdef UNIX}
  CloseSocket(ASock);
  {$else}
  WinSock2.closesocket(ASock);
  {$endif}
end;

// Wait at most ATimeoutMs milliseconds (-1 = no limit) for ASock to turn
// readable, or writable when AWrite. > 0 = ready, 0 = the time ran out
// or a signal cut the wait short (callers re-derive what is left of
// their deadline), < 0 = the wait itself failed.
//
// An error or a hangup counts as ready: the call that follows is what
// turns it into the right close code or failure, and swallowing it here
// would only stall until the deadline.
//
// POSIX uses poll rather than select: select's fd_set caps at
// FD_MAXFDSET (1024) and fpFD_SET silently does nothing above it, which
// would leave the set empty and turn every wait into a full-length false
// timeout in a process holding many descriptors.
function WaitSocket(ASock: TWSPlatformSocket; AWrite: Boolean;
  ATimeoutMs: Integer): Integer;
var
  {$ifdef UNIX}
  PFD: TPollFd;
  {$else}
  Ready, Failed: TFDSet;
  TV: TTimeVal;
  PTV: PTimeVal;
  {$endif}
begin
  {$ifdef UNIX}
  PFD.fd := ASock;
  if AWrite then PFD.events := POLLOUT else PFD.events := POLLIN;
  PFD.revents := 0;
  Result := FpPoll(@PFD, 1, ATimeoutMs);
  if Result < 0 then
  begin
    if fpGetErrno = ESysEINTR then Result := 0;
    Exit;
  end;
  if (Result > 0) and ((PFD.revents and
      (PFD.events or POLLERR or POLLHUP or POLLNVAL)) = 0) then
    Result := 0;
  {$else}
  // One socket per set, and the sets store handles rather than indexing
  // by them, so FD_SETSIZE is moot; WinSock ignores nfds.
  Ready.fd_count := 1;
  Ready.fd_array[0] := ASock;
  Failed.fd_count := 1;
  Failed.fd_array[0] := ASock;
  PTV := nil;
  if ATimeoutMs >= 0 then
  begin
    TV.tv_sec := ATimeoutMs div 1000;
    TV.tv_usec := (ATimeoutMs mod 1000) * 1000;
    PTV := @TV;
  end;
  // A failed non-blocking connect shows up in the exception set only.
  if AWrite then
    Result := WinSock2.select(0, nil, @Ready, @Failed, PTV)
  else
    Result := WinSock2.select(0, @Ready, nil, nil, PTV);
  // WinSock has no EINTR: a failed select is a failed wait.
  if Result = SOCKET_ERROR then Result := -1;
  {$endif}
end;

function SetNonBlocking(ASock: TWSPlatformSocket; AOn: Boolean): Boolean;
var
  {$ifdef UNIX}
  Flags: cint;
  {$else}
  Mode: u_long;
  {$endif}
begin
  {$ifdef UNIX}
  Flags := FpFcntl(ASock, F_GETFL);
  if Flags < 0 then Exit(False);
  if AOn then
    Flags := Flags or O_NONBLOCK
  else
    Flags := Flags and not O_NONBLOCK;
  Result := FpFcntl(ASock, F_SETFL, Flags) = 0;
  {$else}
  Mode := Ord(AOn);
  Result := WinSock2.ioctlsocket(ASock, LongInt(FIONBIO), Mode) = 0;
  {$endif}
end;

// The connect's own outcome, read once the socket turned writable.
function PendingConnectError(ASock: TWSPlatformSocket): Integer;
var
  {$ifdef UNIX}
  Len: TSockLen;
  {$else}
  Len: LongInt;
  {$endif}
begin
  Result := 0;
  Len := SizeOf(Result);
  {$ifdef UNIX}
  if fpGetSockOpt(ASock, SOL_SOCKET, SO_ERROR, @Result, @Len) <> 0 then
    Result := fpGetErrno;
  {$else}
  if WinSock2.getsockopt(ASock, SOL_SOCKET, SO_ERROR, PChar(@Result),
      Len) <> 0 then
    Result := WSAGetLastError;
  {$endif}
end;

// Socket options every client connection carries.
procedure ConfigureClientSocket(ASock: TWSPlatformSocket);
var
  One: Integer;
begin
  One := 1;
  {$ifdef DARWIN}
  fpSetSockOpt(ASock, SOL_SOCKET, WSSoNoSigPipe, @One, SizeOf(One));
  {$endif}
  {$ifdef UNIX}
  fpSetSockOpt(ASock, IPPROTO_TCP, TCP_NODELAY, @One, SizeOf(One));
  {$else}
  WinSock2.setsockopt(ASock, IPPROTO_TCP, TCP_NODELAY, @One, SizeOf(One));
  {$endif}
end;

// Connect one resolved address before ADeadline (WSNoDeadline = as long
// as the OS keeps trying). Returns a connected socket, back in blocking
// mode and configured for the client, or WSSocketInvalid with AError
// saying why — 'timed out' when the deadline ran out first. Callers with
// several addresses try each in turn against one shared deadline.
//
// The connect runs non-blocking so the deadline can cut it short. A
// signal interrupting it (EINTR) does not abort it: the connection keeps
// establishing in the background, so it is awaited like EINPROGRESS.
function ConnectAddress(AFamily: Integer; AAddr: PSockAddr;
  AAddrLen: Integer; ADeadline: QWord; out AError: string): TWSPlatformSocket;
var
  Sock: TWSPlatformSocket;
  Code, Ready: Integer;
  Pending: Boolean;
begin
  Result := WSSocketInvalid;
  AError := '';
  {$ifdef UNIX}
  Sock := fpSocket(AFamily, SOCK_STREAM, 0);
  if Sock < 0 then
  {$else}
  Sock := WinSock2.socket(AFamily, SOCK_STREAM, IPPROTO_TCP);
  if Sock = WSSocketInvalid then
  {$endif}
  begin
    AError := 'socket() failed';
    Exit;
  end;
  try
    if not SetNonBlocking(Sock, True) then
    begin
      AError := 'cannot make the socket non-blocking';
      Exit;
    end;

    {$ifdef UNIX}
    Pending := fpConnect(Sock, AAddr, AAddrLen) <> 0;
    if Pending then Code := fpGetErrno else Code := 0;
    if Pending and (Code <> ESysEINPROGRESS) and (Code <> ESysEINTR) then
    {$else}
    Pending := WinSock2.connect(Sock, AAddr, AAddrLen) = SOCKET_ERROR;
    if Pending then Code := WSAGetLastError else Code := 0;
    if Pending and (Code <> WSAEWOULDBLOCK) then
    {$endif}
    begin
      AError := Format('%s (%d)', [SysErrorMessage(Code), Code]);
      Exit;
    end;

    while Pending do
    begin
      Ready := RemainingMs(ADeadline);
      if Ready = 0 then
      begin
        AError := 'timed out';
        Exit;
      end;
      Ready := WaitSocket(Sock, True, Ready);
      if Ready < 0 then
      begin
        AError := 'readiness wait failed';
        Exit;
      end;
      Pending := Ready = 0; // out of time or interrupted: re-derive, wait on
    end;
    Code := PendingConnectError(Sock);
    if Code <> 0 then
    begin
      AError := Format('%s (%d)', [SysErrorMessage(Code), Code]);
      Exit;
    end;

    if not SetNonBlocking(Sock, False) then
    begin
      AError := 'cannot make the socket blocking again';
      Exit;
    end;
    ConfigureClientSocket(Sock);
    Result := Sock;
  finally
    if Result = WSSocketInvalid then CloseSocketHandle(Sock);
  end;
end;

{$ifdef UNIX}
function ResolveAndConnect(const AHost: string; APort: Integer;
  ADeadline: QWord): TWSPlatformSocket;
var
  SA: TInetSockAddr;
  HE: THostEntry;
  Addr: in_addr;
  Err: string;
begin
  Addr := StrToNetAddr(AHost);
  if Addr.s_addr = 0 then
  begin
    // libc resolves names through nsswitch (files before dns), but FPC's
    // netdb splits the pair: GetHostByName reads /etc/hosts only and
    // returns the address in host byte order, while ResolveHostByName
    // queries the resolv.conf nameservers only and returns network byte
    // order. Names like localhost normally exist only in /etc/hosts, so a
    // DNS-only lookup fails on any resolver that does not synthesize them
    // (plain glibc setups; macOS happens to answer). Match libc: hosts
    // file first — flipping its host-order result — then DNS.
    if GetHostByName(AHost, HE) then
      Addr.s_addr := htonl(HE.Addr.s_addr)
    else if ResolveHostByName(AHost, HE) then
      Addr := HE.Addr
    else
      raise EWSClient.CreateFmt('cannot resolve %s', [AHost]);
  end;

  FillChar(SA, SizeOf(SA), 0);
  SA.sin_family := AF_INET;
  SA.sin_port := htons(APort);
  SA.sin_addr := Addr;
  Result := ConnectAddress(AF_INET, @SA, SizeOf(SA), ADeadline, Err);
  if Result = WSSocketInvalid then
    raise EWSClient.CreateFmt('connect to %s:%d failed: %s',
      [AHost, APort, Err]);
end;
{$endif}

{$ifdef WINDOWS}
type
  PWSAddrInfo = ^TWSAddrInfo;
  TWSAddrInfo = record
    ai_flags: LongInt;
    ai_family: LongInt;
    ai_socktype: LongInt;
    ai_protocol: LongInt;
    ai_addrlen: PtrUInt;
    ai_canonname: PAnsiChar;
    ai_addr: PSockAddr;
    ai_next: PWSAddrInfo;
  end;

function C_getaddrinfo(ANodeName, AServiceName: PAnsiChar;
  AHints: PWSAddrInfo; out AResult: PWSAddrInfo): LongInt; stdcall;
  external WINSOCK2_DLL name 'getaddrinfo';
procedure C_freeaddrinfo(AInfo: PWSAddrInfo); stdcall;
  external WINSOCK2_DLL name 'freeaddrinfo';

var
  WinSockInitialized: Boolean = False;

procedure EnsureWinSockInitialized;
var
  Data: TWSAData;
begin
  if WinSockInitialized then Exit;
  if WSAStartup($0202, Data) <> 0 then
    raise EWSClient.Create('WSAStartup failed');
  WinSockInitialized := True;
end;

function ResolveAndConnect(const AHost: string; APort: Integer;
  ADeadline: QWord): TWSPlatformSocket;
var
  Hints: TWSAddrInfo;
  Info, Current: PWSAddrInfo;
  Host, Service: AnsiString;
  Err: string;
begin
  EnsureWinSockInitialized;
  FillChar(Hints, SizeOf(Hints), 0);
  Hints.ai_family := AF_INET;
  Hints.ai_socktype := SOCK_STREAM;
  Hints.ai_protocol := IPPROTO_TCP;
  Host := AnsiString(AHost);
  Service := AnsiString(IntToStr(APort));
  Info := nil;
  if C_getaddrinfo(PAnsiChar(Host), PAnsiChar(Service), @Hints, Info) <> 0 then
    raise EWSClient.CreateFmt('cannot resolve %s', [AHost]);

  Result := WSSocketInvalid;
  Err := 'no address';
  try
    Current := Info;
    while (Current <> nil) and (Result = WSSocketInvalid) do
    begin
      Result := ConnectAddress(Current^.ai_family, Current^.ai_addr,
        Integer(Current^.ai_addrlen), ADeadline, Err);
      Current := Current^.ai_next;
    end;
  finally
    C_freeaddrinfo(Info);
  end;
  if Result = WSSocketInvalid then
    raise EWSClient.CreateFmt('connect to %s:%d failed: %s',
      [AHost, APort, Err]);
end;
{$endif}

{ TWSClient }

constructor TWSClient.Create;
begin
  inherited;
  FSock := WSSocketInvalid;
  FConnectTimeoutMs := WSDefaultConnectTimeoutMs;
  FHandshakeTimeoutMs := WSDefaultHandshakeTimeoutMs;
  FCloseTimeoutMs := WSDefaultCloseTimeoutMs;
  SetLength(FRecvBuf, 64 * 1024);
end;

destructor TWSClient.Destroy;
begin
  ReleaseTransport;
  FProto.Free;
  inherited;
end;

// Close the TLS session and the socket, whatever state they are in. Safe
// to repeat; the protocol object and the queue are left alone, so
// CloseCode and undrained messages stay readable.
procedure TWSClient.ReleaseTransport;
begin
  if FTls.Active then
  try
    CloseTransportSecurity(FTls);
  except
    // A session that already failed may fail its close_notify too; the
    // socket below goes regardless.
    on ETransportSecurityError do;
  end;
  if FSock <> WSSocketInvalid then
  begin
    CloseSocketHandle(FSock);
    FSock := WSSocketInvalid;
  end;
end;

// Everything the previous connection left behind, before a new one.
procedure TWSClient.ResetConnection;
begin
  ReleaseTransport;
  FreeAndNil(FProto);
  FQueue := nil;
  FQHead := 0;
  FQTail := 0;
  FDeflate := Default(TWSDeflateParams);
  FTlsError := '';
  FOpen := False;
end;

// lwpt raises ETransportSecurityError for a failed TLS read or write (a
// bad record, a reset, an EOF without close_notify). Inside a session
// that is a dead connection like any other: report it as one (-1), so
// the callers' FOpen := False path handles it and nothing escapes a send,
// a read or Close.
function TWSClient.TlsRead(P: PByte; ALen: Integer): Integer;
begin
  try
    Result := TransportSecurityRead(FTls, PWSByteSpan(P)^, ALen);
  except
    on E: ETransportSecurityError do
    begin
      FTlsError := E.Message;
      Result := -1;
    end;
  end;
end;

function TWSClient.TlsWrite(P: PByte; ALen: Integer): Integer;
begin
  try
    Result := TransportSecurityWrite(FTls, P, ALen);
  except
    on E: ETransportSecurityError do
    begin
      FTlsError := E.Message;
      Result := -1;
    end;
  end;
end;

// A signal landing while the call blocks (EINTR) is retried: it says
// nothing about the connection.
function TWSClient.RawRead(P: PByte; ALen: Integer): Integer;
begin
  if FUseTls then Exit(TlsRead(P, ALen));
  {$ifdef UNIX}
  repeat
    Result := fpRecv(FSock, P, ALen, 0);
  until (Result >= 0) or (fpGetErrno <> ESysEINTR);
  {$else}
  Result := WinSock2.recv(FSock, P^, ALen, 0);
  {$endif}
end;

function TWSClient.RawWrite(P: PByte; ALen: Integer): Integer;
begin
  if FUseTls then Exit(TlsWrite(P, ALen));
  {$ifdef UNIX}
  repeat
    Result := fpSend(FSock, P, ALen, WSSendFlags);
  until (Result >= 0) or (fpGetErrno <> ESysEINTR);
  {$else}
  Result := WinSock2.send(FSock, P^, ALen, 0);
  {$endif}
end;

procedure TWSClient.FlushOut;
var
  N, W: Integer;
begin
  while FProto.OutPending > 0 do
  begin
    N := FProto.OutPending;
    W := RawWrite(FProto.OutPtr, N);
    if W <= 0 then
    begin
      FOpen := False;
      Exit;
    end;
    FProto.OutConsume(W);
  end;
end;

procedure TWSClient.ProtoMessage(AText: Boolean; P: PByte; ALen: NativeInt);
var
  N: Integer;
  Returned: Boolean;
begin
  if Assigned(FOnMessage) then
  begin
    // A send inside an earlier handler call of this same read may have
    // found the socket dead; the rest of the read is not the
    // application's to see.
    if not FOpen then Exit;
    FDelivering := True;
    Returned := False;
    try
      FOnMessage(Self, AText, P, ALen);
      Returned := True;
    finally
      FDelivering := False;
      // An exception is unwinding Ingest mid-read: the rest of the read
      // is lost, so the stream cannot be trusted again.
      if not Returned then FOpen := False;
    end;
    Exit;
  end;
  N := Length(FQueue);
  if FQTail = N then
  begin
    if N = 0 then N := 4;
    SetLength(FQueue, N * 2);
  end;
  FQueue[FQTail].Text := AText;
  SetLength(FQueue[FQTail].Data, ALen);
  if ALen > 0 then Move(P^, FQueue[FQTail].Data[0], ALen);
  Inc(FQTail);
end;

// No deadline for the TLS handshake itself, deliberately: lwpt keeps the
// deadline it is given armed on the session for good, and every later
// read or write that has to wait re-checks it — on macOS that is any
// record split across TCP segments — so a long-lived connection would
// fail once the handshake budget had passed. See HandshakeTimeoutMs.
procedure TWSClient.StartTls(const AHost: string);
begin
  try
    StartTransportSecurity(FTls, FSock, AHost);
  except
    on E: ETransportSecurityError do
      raise EWSClient.Create('TLS handshake failed: ' + E.Message);
  end;
  if not FTls.Active then
    raise EWSClient.Create('TLS handshake failed');
end;

// Read the upgrade response up to its header terminator; bytes after it
// (AHeaderEnd onwards) are frame data the server pipelined behind the
// 101. Every blocking read waits on a readiness poll sized by what is
// left of ADeadline first.
function TWSClient.ReadUpgradeResponse(ADeadline: QWord;
  out AHeaderEnd: Integer; const APeer: string): RawByteString;
var
  Buf: array[0..8191] of Byte;
  Got, Ready: Integer;
begin
  Result := '';
  AHeaderEnd := 0;
  repeat
    if ADeadline <> WSNoDeadline then
    begin
      Ready := RemainingMs(ADeadline);
      if Ready > 0 then Ready := WaitSocket(FSock, False, Ready);
      if Ready < 0 then
        raise EWSClient.Create('connection lost in handshake');
      if Ready = 0 then
      begin
        // The time ran out, or a signal cut the wait short.
        if RemainingMs(ADeadline) = 0 then
          raise EWSClient.CreateFmt('handshake with %s timed out after %d ms',
            [APeer, FHandshakeTimeoutMs]);
        Continue;
      end;
    end;
    Got := RawRead(@Buf[0], SizeOf(Buf));
    if Got <= 0 then
    begin
      if FTlsError <> '' then
        raise EWSClient.Create('connection lost in handshake: ' + FTlsError);
      raise EWSClient.Create('connection lost in handshake');
    end;
    SetLength(Result, Length(Result) + Got);
    Move(Buf[0], Result[Length(Result) - Got + 1], Got);
    if Length(Result) > 64 * 1024 then
      raise EWSClient.Create('handshake response too large');
    AHeaderEnd := HandshakeFindEnd(Result);
  until AHeaderEnd > 0;
end;

procedure TWSClient.Connect(const AUrl: string; AOfferDeflate: Boolean;
  AMaxMessage: NativeInt);
var
  Host, Path, Key, Req, Err, Peer: string;
  Port: Integer;
  Raw: RawByteString;
  HdrEnd: Integer;
  Deadline: QWord;
begin
  // Inside OnMessage the previous connection's read is still running on
  // the protocol object a reconnect would free.
  if FDelivering then
    raise EWSClient.Create('cannot connect from inside OnMessage');
  if FOpen then raise EWSClient.Create('already connected');
  ResetConnection;
  ParseWsUrl(AUrl, FUseTls, Host, Port, Path);
  Peer := Host + ':' + IntToStr(Port);

  try
    FSock := ResolveAndConnect(Host, Port, DeadlineAfter(FConnectTimeoutMs));
    Deadline := DeadlineAfter(FHandshakeTimeoutMs);
    if FUseTls then StartTls(Host);

    Key := ClientGenerateKey;
    if (Port = 80) or (Port = 443) then
      Req := ClientBuildRequest(Host, Path, Key, AOfferDeflate)
    else
      Req := ClientBuildRequest(Peer, Path, Key, AOfferDeflate);
    if RawWrite(@Req[1], Length(Req)) <> Length(Req) then
      raise EWSClient.Create('handshake send failed');

    Raw := ReadUpgradeResponse(Deadline, HdrEnd, Peer);
    if not ClientParseResponse(Copy(Raw, 1, HdrEnd), Key, AOfferDeflate,
        FDeflate, Err) then
      raise EWSClient.Create('handshake rejected: ' + Err);

    FProto := TWSProtocol.Create(wsrClient, FDeflate, AMaxMessage);
    FProto.OnMessage := ProtoMessage;
    FOpen := True;

    // Anything the server pipelined behind its 101 goes straight in.
    if HdrEnd < Length(Raw) then
      if not FProto.Ingest(@Raw[HdrEnd + 1], Length(Raw) - HdrEnd) then
        FOpen := False;
    FlushOut;
  except
    // Nothing half-open survives a failed Connect (a raising OnMessage
    // on a pipelined message included). The protocol object stays for
    // CloseCode until the next Connect or Free.
    FOpen := False;
    ReleaseTransport;
    raise;
  end;
end;

function TWSClient.PumpOnce: Boolean;
var
  Got: Integer;
begin
  Result := False;
  Got := RawRead(@FRecvBuf[0], Length(FRecvBuf));
  if Got <= 0 then
  begin
    FOpen := False;
    Exit;
  end;
  Result := FProto.Ingest(@FRecvBuf[0], Got);
  FlushOut; // pongs / close echoes leave immediately
  if not Result then FOpen := False;
  if FProto.CloseDone then FOpen := False;
end;

// True when the socket has bytes to read within ATimeoutMs milliseconds
// (0 = one non-blocking check). An unrecoverable readiness failure is
// recorded the way every other death here is — FOpen goes False — so the
// caller ends the connection instead of spinning on a permanent error; a
// signal only cuts the wait short, and the caller re-derives the rest.
// The bounded ReadMessage overload documents what this cannot see over
// wss://.
function TWSClient.WaitReadable(ATimeoutMs: Integer): Boolean;
var
  Ready: Integer;
begin
  Ready := WaitSocket(FSock, False, ATimeoutMs);
  if Ready < 0 then FOpen := False;
  Result := Ready > 0;
end;

procedure TWSClient.PopMessage(out AText: Boolean; out AData: TBytes);
begin
  AText := FQueue[FQHead].Text;
  AData := FQueue[FQHead].Data;
  FQueue[FQHead].Data := nil;
  Inc(FQHead);
  if FQHead = FQTail then
  begin
    FQHead := 0;
    FQTail := 0;
  end;
end;

procedure TWSClient.RefuseReadInHandler;
begin
  // Ingest is not re-entrant, and FRecvBuf is what the running handler
  // may be looking at.
  if FDelivering then
    raise EWSClient.Create('cannot read from inside OnMessage');
end;

function TWSClient.ReadMessage(out AText: Boolean; out AData: TBytes): Boolean;
begin
  RefuseReadInHandler;
  while FQHead = FQTail do
  begin
    if not FOpen then Exit(False);
    PumpOnce;
  end;
  PopMessage(AText, AData);
  Result := True;
end;

function TWSClient.ReadMessage(out AText: Boolean; out AData: TBytes;
  ATimeoutMs: Integer): TWSReadResult;
var
  Deadline: QWord;
  Remaining: Int64;
begin
  RefuseReadInHandler;
  // Already queued: no clock, no poll, no syscall.
  if FQHead <> FQTail then
  begin
    PopMessage(AText, AData);
    Exit(wrrMessage);
  end;
  if not FOpen then Exit(wrrClosed);

  if ATimeoutMs <= 0 then
  begin
    // Exactly one non-blocking round. A peer that keeps the socket
    // readable must not be able to hold this call for another pass.
    // (Over wss even this round can block: the pump reads through the
    // TLS layer, which waits for a whole record — see the overload
    // comment.)
    if WaitReadable(0) then PumpOnce;
    if FQHead <> FQTail then
    begin
      PopMessage(AText, AData);
      Exit(wrrMessage);
    end;
    if not FOpen then Exit(wrrClosed);
    Exit(wrrTimeout);
  end;

  Deadline := WSMonotonicMs + QWord(ATimeoutMs);
  Remaining := ATimeoutMs;
  // Remaining is re-derived at the foot of the loop, so a wait cut short
  // (EINTR, a partial frame) resumes with what is left and a wait that
  // ran its full length falls straight out instead of polling again.
  while Remaining > 0 do
  begin
    if WaitReadable(Integer(Remaining)) then
      PumpOnce; // a partial frame is fine; the loop re-derives the rest
    if FQHead <> FQTail then
    begin
      PopMessage(AText, AData);
      Exit(wrrMessage);
    end;
    if not FOpen then Exit(wrrClosed);
    Remaining := Int64(Deadline) - Int64(WSMonotonicMs);
  end;
  Result := wrrTimeout;
end;

procedure TWSClient.SendText(const S: RawByteString);
begin
  if not FOpen then raise EWSClient.Create('not connected');
  FProto.SendText(S);
  FlushOut;
end;

procedure TWSClient.SendBinary(P: PByte; ALen: NativeInt);
begin
  if not FOpen then raise EWSClient.Create('not connected');
  FProto.SendBinary(P, ALen);
  FlushOut;
end;

procedure TWSClient.Ping(const S: RawByteString);
begin
  if not FOpen then raise EWSClient.Create('not connected');
  if S <> '' then
    FProto.SendPing(@S[1], Length(S))
  else
    FProto.SendPing(nil, 0);
  FlushOut;
end;

// Pump until the peer's close echo arrives or CloseTimeoutMs runs out.
// Messages arriving meanwhile still queue (or reach OnMessage).
procedure TWSClient.AwaitCloseEcho;
var
  Deadline: QWord;
  Remaining: Int64;
begin
  if FCloseTimeoutMs <= 0 then Exit;
  Deadline := WSMonotonicMs + QWord(FCloseTimeoutMs);
  Remaining := FCloseTimeoutMs;
  while FOpen and not FProto.CloseDone and (Remaining > 0) do
  begin
    if WaitReadable(Integer(Remaining)) then PumpOnce;
    Remaining := Int64(Deadline) - Int64(WSMonotonicMs);
  end;
end;

procedure TWSClient.Close(ACode: Word; const AReason: string);
begin
  if FProto = nil then
  begin
    ReleaseTransport;
    Exit;
  end;
  if FDelivering then
  begin
    // Inside OnMessage the read below us is still running and cannot be
    // re-entered to wait for the echo: send the close frame and leave the
    // echo to the reads that follow, or to a later Close.
    if FOpen then
    begin
      FProto.SendClose(ACode, AReason);
      FlushOut;
    end;
    Exit;
  end;
  // CloseDone, not CloseSent: a close sent from inside OnMessage still
  // gets its bounded wait for the echo here.
  if FOpen and not FProto.CloseDone then
  begin
    FProto.SendClose(ACode, AReason); // no-op once a close went out
    FlushOut;
    AwaitCloseEcho;
  end;
  FOpen := False;
  ReleaseTransport;
end;

function TWSClient.CloseCode: Word;
begin
  if FProto <> nil then Result := FProto.CloseCode else Result := 1006;
end;

function TWSClient.CloseReason: string;
begin
  if FProto <> nil then Result := FProto.CloseReason else Result := '';
end;

end.
