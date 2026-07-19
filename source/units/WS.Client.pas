unit WS.Client;

// Blocking RFC 6455 client. ws:// is raw TCP; wss:// rides lwpt's
// TransportSecurity (OpenSSL on Linux, SecureTransport on macOS, Schannel
// on Windows — same backend the lwpt HTTP client trusts).
//
// All protocol behaviour lives in TWSProtocol; this unit is the socket,
// the TLS shim, the opening handshake, and a pump loop. ReadMessage blocks
// until a complete message arrives (pings are answered invisibly along the
// way) or the connection ends.

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
  WS.Handshake, WS.Protocol;

type
  EWSClient = class(Exception);

  TWSPlatformSocket = Tsocket;

const
  {$ifdef WINDOWS}
  WSSocketInvalid = INVALID_SOCKET;
  {$else}
  WSSocketInvalid = TWSPlatformSocket(-1);
  {$endif}

type

  TWSClient = class
  private
    FSock: TWSPlatformSocket;
    FTls: TTransportSecurityConnection;
    FUseTls: Boolean;
    FProto: TWSProtocol;
    FOpen: Boolean;
    FDeflate: TWSDeflateParams;

    // pending complete messages (several can arrive in one TCP read)
    FQueue: array of record Text: Boolean; Data: TBytes; end;
    FQHead, FQTail: Integer;

    FRecvBuf: TBytes;

    procedure ProtoMessage(AText: Boolean; P: PByte; ALen: NativeInt);
    function RawRead(P: PByte; ALen: Integer): Integer;
    function RawWrite(P: PByte; ALen: Integer): Integer;
    procedure FlushOut;
    function PumpOnce: Boolean;
  public
    constructor Create;
    destructor Destroy; override;

    // url: ws://host[:port]/path or wss://host[:port]/path
    procedure Connect(const AUrl: string; AOfferDeflate: Boolean = False;
      AMaxMessage: NativeInt = 16 * 1024 * 1024);

    procedure SendText(const S: RawByteString);
    procedure SendBinary(P: PByte; ALen: NativeInt);
    procedure Ping(const S: RawByteString = '');

    // Blocks until a message arrives. False = connection closed (see
    // CloseCode/CloseReason) or failed.
    function ReadMessage(out AText: Boolean; out AData: TBytes): Boolean;

    // Initiate the closing handshake and wait (bounded) for the echo.
    procedure Close(ACode: Word = 1000; const AReason: string = '');

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

{$ifdef UNIX}
function ResolveAndConnect(const AHost: string; APort: Integer): Tsocket;
var
  SA: TInetSockAddr;
  HE: THostEntry;
  Addr: in_addr;
  One: Integer;
begin
  Addr := StrToNetAddr(AHost);
  if Addr.s_addr = 0 then
  begin
    if not ResolveHostByName(AHost, HE) then
      raise EWSClient.CreateFmt('cannot resolve %s', [AHost]);
    Addr := HE.Addr;
  end;

  Result := fpSocket(AF_INET, SOCK_STREAM, 0);
  if Result < 0 then raise EWSClient.Create('socket() failed');

  FillChar(SA, SizeOf(SA), 0);
  SA.sin_family := AF_INET;
  SA.sin_port := htons(APort);
  SA.sin_addr := Addr;
  if fpConnect(Result, @SA, SizeOf(SA)) <> 0 then
  begin
    CloseSocket(Result);
    raise EWSClient.CreateFmt('connect to %s:%d failed', [AHost, APort]);
  end;

  One := 1;
  fpSetSockOpt(Result, IPPROTO_TCP, TCP_NODELAY, @One, SizeOf(One));
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

function ResolveAndConnect(const AHost: string;
  APort: Integer): TWSPlatformSocket;
var
  Hints: TWSAddrInfo;
  Info, Current: PWSAddrInfo;
  Host, Service: AnsiString;
  One: Integer;
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
  try
    Current := Info;
    while Current <> nil do
    begin
      Result := WinSock2.socket(Current^.ai_family, Current^.ai_socktype,
        Current^.ai_protocol);
      if Result <> WSSocketInvalid then
      begin
        if WinSock2.connect(Result, Current^.ai_addr,
            Current^.ai_addrlen) = 0 then Break;
        WinSock2.closesocket(Result);
        Result := WSSocketInvalid;
      end;
      Current := Current^.ai_next;
    end;
  finally
    C_freeaddrinfo(Info);
  end;
  if Result = WSSocketInvalid then
    raise EWSClient.CreateFmt('connect to %s:%d failed', [AHost, APort]);

  One := 1;
  WinSock2.setsockopt(Result, IPPROTO_TCP, TCP_NODELAY, @One, SizeOf(One));
end;
{$endif}

{ TWSClient }

constructor TWSClient.Create;
begin
  inherited;
  FSock := WSSocketInvalid;
  SetLength(FRecvBuf, 64 * 1024);
end;

destructor TWSClient.Destroy;
begin
  if FUseTls and FTls.Active then CloseTransportSecurity(FTls);
  if FSock <> WSSocketInvalid then
  begin
    {$ifdef UNIX}
    CloseSocket(FSock);
    {$else}
    WinSock2.closesocket(FSock);
    {$endif}
  end;
  FProto.Free;
  inherited;
end;

function TWSClient.RawRead(P: PByte; ALen: Integer): Integer;
begin
  if FUseTls then
    Result := TransportSecurityRead(FTls, PByte(P)^, ALen)
  else
    {$ifdef UNIX}
    Result := fpRecv(FSock, P, ALen, 0);
    {$else}
    Result := WinSock2.recv(FSock, P^, ALen, 0);
    {$endif}
end;

function TWSClient.RawWrite(P: PByte; ALen: Integer): Integer;
begin
  if FUseTls then
    Result := TransportSecurityWrite(FTls, P, ALen)
  else
    {$ifdef UNIX}
    Result := fpSend(FSock, P, ALen, 0);
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
begin
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

procedure TWSClient.Connect(const AUrl: string; AOfferDeflate: Boolean;
  AMaxMessage: NativeInt);
var
  Host, Path, Key, Req, Err: string;
  Port: Integer;
  Raw: RawByteString;
  Buf: array[0..8191] of Byte;
  Got, HdrEnd: Integer;
begin
  if FOpen then raise EWSClient.Create('already connected');
  ParseWsUrl(AUrl, FUseTls, Host, Port, Path);

  {$ifdef UNIX}
  FSock := ResolveAndConnect(Host, Port);
  {$else}
  FSock := ResolveAndConnect(Host, Port);
  {$endif}

  if FUseTls then
  begin
    StartTransportSecurity(FTls, FSock, Host);
    if not FTls.Active then
      raise EWSClient.Create('TLS handshake failed');
  end;

  Key := ClientGenerateKey;
  if (Port = 80) or (Port = 443) then
    Req := ClientBuildRequest(Host, Path, Key, AOfferDeflate)
  else
    Req := ClientBuildRequest(Host + ':' + IntToStr(Port), Path, Key,
      AOfferDeflate);
  if RawWrite(@Req[1], Length(Req)) <> Length(Req) then
    raise EWSClient.Create('handshake send failed');

  // Read until the header terminator. Bytes after it are frame data.
  Raw := '';
  repeat
    Got := RawRead(@Buf[0], SizeOf(Buf));
    if Got <= 0 then raise EWSClient.Create('connection lost in handshake');
    SetLength(Raw, Length(Raw) + Got);
    Move(Buf[0], Raw[Length(Raw) - Got + 1], Got);
    if Length(Raw) > 64 * 1024 then
      raise EWSClient.Create('handshake response too large');
    HdrEnd := HandshakeFindEnd(Raw);
  until HdrEnd > 0;

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

function TWSClient.ReadMessage(out AText: Boolean; out AData: TBytes): Boolean;
begin
  while FQHead = FQTail do
  begin
    if not FOpen then Exit(False);
    PumpOnce;
  end;
  AText := FQueue[FQHead].Text;
  AData := FQueue[FQHead].Data;
  FQueue[FQHead].Data := nil;
  Inc(FQHead);
  if FQHead = FQTail then
  begin
    FQHead := 0;
    FQTail := 0;
  end;
  Result := True;
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

procedure TWSClient.Close(ACode: Word; const AReason: string);
var
  Spins: Integer;
begin
  if FProto = nil then Exit;
  if FOpen and not FProto.CloseSent then
  begin
    FProto.SendClose(ACode, AReason);
    FlushOut;
    // Bounded wait for the peer's close echo; then drop TCP regardless.
    Spins := 0;
    while FOpen and not FProto.CloseDone and (Spins < 64) do
    begin
      PumpOnce;
      Inc(Spins);
    end;
  end;
  FOpen := False;
  if FUseTls and FTls.Active then CloseTransportSecurity(FTls);
  if FSock <> WSSocketInvalid then
  begin
    {$ifdef UNIX}
    CloseSocket(FSock);
    {$else}
    WinSock2.closesocket(FSock);
    {$endif}
    FSock := WSSocketInvalid;
  end;
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
