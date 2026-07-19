unit WS.Transport.Iocp;

// Windows transport: one IOCP thread implementing the WS.Transport
// completion contract. AcceptEx, WSARecv, and WSASend are always armed
// overlapped; every callback and deferred free runs on the thread in Run.

{$I Shared.inc}

interface

{$ifdef WINDOWS}

uses
  SysUtils,
  Windows,

  WinSock2,
  WS.Transport;

const
  IocpReceiveBufferSize = 64 * 1024;
  IocpSendBufferSize = 256 * 1024;

type
  TWSIocpTransport = class;

  TWSIocpConn = class(TWSTransportConn)
  private
    FTransport: TWSIocpTransport;
    FSocket: TSocket;
    FReceiveOverlapped: TOverlapped;
    FSendOverlapped: TOverlapped;
    FReceiveBuffer: array[0..IocpReceiveBufferSize - 1] of Byte;
    FSendBuffer: array[0..IocpSendBufferSize - 1] of Byte;
    FOutstanding: Integer;
    FSendInFlight: Boolean;
    FDead: Boolean;
    procedure ArmReceive;
    procedure CloseConnectionSocket;
    procedure TryFinalize;
  public
    function SubmitSend(P: PByte; ALen: NativeInt): NativeInt; override;
    procedure SubmitClose; override;
  end;

  TWSIocpTransport = class(TWSTransport)
  private
    FListenSocket: TSocket;
    FAcceptSocket: TSocket;
    FCompletionPort: THandle;
    FAcceptOverlapped: TOverlapped;
    FAcceptBuffer: array[0..(2 * (SizeOf(TSockAddrIn) + 16)) - 1] of Byte;
    FAcceptPending: Boolean;
    FOpen: Boolean;
    FRunning: Boolean;
    FStopping: Boolean;
    FShutdownDone: Boolean;
    FWinSockStarted: Boolean;
    FNextId: NativeUInt;
    FLive: array of TWSIocpConn;
    FLiveCount: Integer;
    procedure ArmAccept;
    procedure Track(AConn: TWSIocpConn);
    procedure Untrack(AConn: TWSIocpConn);
    procedure RemoteClosed(AConn: TWSIocpConn);
    procedure HandleAcceptCompletion(ASucceeded: Boolean);
    procedure HandleConnectionCompletion(AConn: TWSIocpConn;
      AOverlapped: POverlapped; ABytes: DWORD; ASucceeded: Boolean);
    procedure WaitAndDispatch(ATimeout: DWORD);
  public
    constructor Create(APort: Word; const ATls: TWSTransportTls);
    destructor Destroy; override;
    procedure Run(ATimeoutMs: Integer = -1); override;
    procedure Stop; override;
    procedure Open; override;
    procedure Shutdown; override;
  end;

{$endif}

implementation

{$ifdef WINDOWS}

const
  WSA_FLAG_OVERLAPPED = $00000001;
  SO_UPDATE_ACCEPT_CONTEXT = $700B;
  WinErrorIoPending = 997;
  InfiniteWait = DWORD($FFFFFFFF);
  ListenerCompletionKey = PtrUInt(1);
  WakeCompletionKey = PtrUInt(2);
  LiveTableGrowth = 64;
  AcceptAddressLength = SizeOf(TSockAddrIn) + 16;

type
  PWSIocpBuffer = ^TWSIocpBuffer;
  TWSIocpBuffer = record
    Len: DWORD;
    Buf: PAnsiChar;
  end;

// FPC 3.2.2's Windows headers are incomplete across Win32/Win64. Keep
// the small overlapped surface local and bind every export explicitly.
function C_WSASocketW(AFamily, ASocketType, AProtocol: Integer;
  AProtocolInfo: Pointer; AGroup, AFlags: DWORD): TSocket; stdcall;
  external WINSOCK2_DLL name 'WSASocketW';
// AcceptEx is a static export of mswsock.dll; the
// SIO_GET_EXTENSION_FUNCTION_POINTER route saves an internal per-call
// lookup but failed with WSAEFAULT under i386 FPC — the direct import
// binds once at load and needs no resolution machinery.
function C_AcceptEx(AListenSocket, AAcceptSocket: TSocket;
  AOutputBuffer: Pointer; AReceiveDataLength, ALocalAddressLength,
  ARemoteAddressLength: DWORD; ABytesReceived: PDWORD;
  AOverlapped: POverlapped): BOOL; stdcall;
  external 'mswsock.dll' name 'AcceptEx';
function C_WSARecv(ASocket: TSocket; ABuffers: PWSIocpBuffer;
  ABufferCount: DWORD; ABytesReceived, AFlags: PDWORD;
  AOverlapped: POverlapped; ACompletionRoutine: Pointer): Integer; stdcall;
  external WINSOCK2_DLL name 'WSARecv';
function C_WSASend(ASocket: TSocket; ABuffers: PWSIocpBuffer;
  ABufferCount: DWORD; ABytesSent: PDWORD; AFlags: DWORD;
  AOverlapped: POverlapped; ACompletionRoutine: Pointer): Integer; stdcall;
  external WINSOCK2_DLL name 'WSASend';
function C_CreateIoCompletionPort(AFileHandle, AExistingPort: THandle;
  ACompletionKey: PtrUInt; AConcurrentThreads: DWORD): THandle; stdcall;
  external 'kernel32.dll' name 'CreateIoCompletionPort';
function C_GetQueuedCompletionStatus(ACompletionPort: THandle;
  var ABytesTransferred: DWORD; var ACompletionKey: PtrUInt;
  out AOverlapped: POverlapped; ATimeout: DWORD): BOOL; stdcall;
  external 'kernel32.dll' name 'GetQueuedCompletionStatus';
function C_PostQueuedCompletionStatus(ACompletionPort: THandle;
  ABytesTransferred: DWORD; ACompletionKey: PtrUInt;
  AOverlapped: POverlapped): BOOL; stdcall;
  external 'kernel32.dll' name 'PostQueuedCompletionStatus';

{ TWSIocpConn }

procedure TWSIocpConn.CloseConnectionSocket;
begin
  if FSocket = INVALID_SOCKET then Exit;
  WinSock2.closesocket(FSocket);
  FSocket := INVALID_SOCKET;
end;

procedure TWSIocpConn.TryFinalize;
begin
  if (not FDead) or (FOutstanding <> 0) then Exit;
  FTransport.Untrack(Self);
  Free;
end;

procedure TWSIocpConn.ArmReceive;
var
  Buffer: TWSIocpBuffer;
  Flags: DWORD;
begin
  if FDead then Exit;
  FillChar(FReceiveOverlapped, SizeOf(FReceiveOverlapped), 0);
  Buffer.Len := SizeOf(FReceiveBuffer);
  Buffer.Buf := PAnsiChar(@FReceiveBuffer[0]);
  Flags := 0;
  Inc(FOutstanding);
  if C_WSARecv(FSocket, @Buffer, 1, nil, @Flags,
      @FReceiveOverlapped, nil) = SOCKET_ERROR then
    if WSAGetLastError <> WinErrorIoPending then
    begin
      Dec(FOutstanding);
      FTransport.RemoteClosed(Self);
    end;
end;

function TWSIocpConn.SubmitSend(P: PByte; ALen: NativeInt): NativeInt;
var
  Buffer: TWSIocpBuffer;
  Accepted: NativeInt;
begin
  if FDead then Exit(-1);
  if FSendInFlight then Exit(0);
  if ALen <= 0 then Exit(0);
  Accepted := ALen;
  if Accepted > SizeOf(FSendBuffer) then Accepted := SizeOf(FSendBuffer);
  Move(P^, FSendBuffer[0], Accepted);

  FillChar(FSendOverlapped, SizeOf(FSendOverlapped), 0);
  Buffer.Len := Accepted;
  Buffer.Buf := PAnsiChar(@FSendBuffer[0]);
  FSendInFlight := True;
  Inc(FOutstanding);
  if C_WSASend(FSocket, @Buffer, 1, nil, 0,
      @FSendOverlapped, nil) = SOCKET_ERROR then
    if WSAGetLastError <> WinErrorIoPending then
    begin
      Dec(FOutstanding);
      FSendInFlight := False;
      FDead := True;
      CloseConnectionSocket;
      Exit(-1);
    end;
  Result := Accepted;
end;

procedure TWSIocpConn.SubmitClose;
begin
  if not FDead then
  begin
    FDead := True;
    CloseConnectionSocket;
  end;
  TryFinalize;
end;

{ TWSIocpTransport }

constructor TWSIocpTransport.Create(APort: Word;
  const ATls: TWSTransportTls);
var
  Address: TSockAddrIn;
  AddressLength: Integer;
  Data: TWSAData;
  One: Integer;
begin
  inherited Create;
  FListenSocket := INVALID_SOCKET;
  FAcceptSocket := INVALID_SOCKET;
  if ATls.Enabled then
    raise Exception.Create(
      'iocp transport has no TLS yet (tracked as lwpt#70: accept-side ' +
      'TransportSecurity); run behind a TLS-terminating proxy');

  if WSAStartup($0202, Data) <> 0 then
    raise Exception.Create('WSAStartup failed');
  FWinSockStarted := True;

  FListenSocket := C_WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
    nil, 0, WSA_FLAG_OVERLAPPED);
  if FListenSocket = INVALID_SOCKET then
    raise Exception.CreateFmt('WSASocketW() failed (%d)', [WSAGetLastError]);
  One := 1;
  WinSock2.setsockopt(FListenSocket, SOL_SOCKET, SO_REUSEADDR,
    @One, SizeOf(One));

  FillChar(Address, SizeOf(Address), 0);
  Address.sin_family := AF_INET;
  Address.sin_port := htons(APort);
  Address.sin_addr.S_addr := INADDR_ANY;
  if WinSock2.bind(FListenSocket, @Address, SizeOf(Address)) <> 0 then
    raise Exception.CreateFmt('bind to port %d failed (%d)', [APort, WSAGetLastError]);
  if WinSock2.listen(FListenSocket, 511) <> 0 then
    raise Exception.CreateFmt('listen() failed (%d)', [WSAGetLastError]);

  AddressLength := SizeOf(Address);
  if WinSock2.getsockname(FListenSocket, Address, AddressLength) <> 0 then
    raise Exception.CreateFmt('getsockname() failed (%d)', [WSAGetLastError]);
  SetPort(ntohs(Address.sin_port));

  FCompletionPort := C_CreateIoCompletionPort(THandle(FListenSocket), 0,
    ListenerCompletionKey, 1);
  if FCompletionPort = 0 then
    raise Exception.CreateFmt('CreateIoCompletionPort() failed (%d)', [GetLastError]);

end;

destructor TWSIocpTransport.Destroy;
begin
  Shutdown;
  if FAcceptSocket <> INVALID_SOCKET then
    WinSock2.closesocket(FAcceptSocket);
  if FListenSocket <> INVALID_SOCKET then
    WinSock2.closesocket(FListenSocket);
  if FCompletionPort <> 0 then CloseHandle(FCompletionPort);
  if FWinSockStarted then WSACleanup;
  inherited;
end;

procedure TWSIocpTransport.Track(AConn: TWSIocpConn);
begin
  if FLiveCount = Length(FLive) then
    SetLength(FLive, FLiveCount + LiveTableGrowth);
  FLive[FLiveCount] := AConn;
  Inc(FLiveCount);
end;

procedure TWSIocpTransport.Untrack(AConn: TWSIocpConn);
var
  I: Integer;
begin
  for I := 0 to FLiveCount - 1 do
    if FLive[I] = AConn then
    begin
      FLive[I] := FLive[FLiveCount - 1];
      FLive[FLiveCount - 1] := nil;
      Dec(FLiveCount);
      Exit;
    end;
end;

procedure TWSIocpTransport.RemoteClosed(AConn: TWSIocpConn);
begin
  if AConn.FDead then Exit;
  AConn.FDead := True;
  AConn.CloseConnectionSocket;
  // Pin the object until OnClosed returns, including immediate arm
  // failures where there is no completed operation holding the pin.
  Inc(AConn.FOutstanding);
  if Assigned(OnClosed) then OnClosed(AConn);
  Dec(AConn.FOutstanding);
  AConn.TryFinalize;
end;

procedure TWSIocpTransport.ArmAccept;
var
  Bytes: DWORD;
begin
  if FStopping or FAcceptPending then Exit;
  FAcceptSocket := C_WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
    nil, 0, WSA_FLAG_OVERLAPPED);
  if FAcceptSocket = INVALID_SOCKET then
    raise Exception.Create('accept WSASocketW() failed');
  FillChar(FAcceptOverlapped, SizeOf(FAcceptOverlapped), 0);
  FillChar(FAcceptBuffer, SizeOf(FAcceptBuffer), 0);
  Bytes := 0;
  if not C_AcceptEx(FListenSocket, FAcceptSocket, @FAcceptBuffer[0], 0,
      AcceptAddressLength, AcceptAddressLength, @Bytes,
      @FAcceptOverlapped) then
    if WSAGetLastError <> WinErrorIoPending then
    begin
      WinSock2.closesocket(FAcceptSocket);
      FAcceptSocket := INVALID_SOCKET;
      raise Exception.Create('AcceptEx() failed');
    end;
  FAcceptPending := True;
end;

procedure TWSIocpTransport.HandleAcceptCompletion(ASucceeded: Boolean);
var
  AcceptedSocket: TSocket;
  Conn: TWSIocpConn;
  One: Integer;
begin
  FAcceptPending := False;
  AcceptedSocket := FAcceptSocket;
  FAcceptSocket := INVALID_SOCKET;
  if ASucceeded and (not FStopping) then
  begin
    if WinSock2.setsockopt(AcceptedSocket, SOL_SOCKET,
        SO_UPDATE_ACCEPT_CONTEXT, @FListenSocket,
        SizeOf(FListenSocket)) = 0 then
    begin
      One := 1;
      WinSock2.setsockopt(AcceptedSocket, IPPROTO_TCP, TCP_NODELAY,
        @One, SizeOf(One));
      Conn := TWSIocpConn.Create;
      Conn.FTransport := Self;
      Conn.FSocket := AcceptedSocket;
      if C_CreateIoCompletionPort(THandle(AcceptedSocket), FCompletionPort,
          PtrUInt(Pointer(Conn)), 0) <> 0 then
      begin
        Inc(FNextId);
        Conn.Id := FNextId;
        Track(Conn);
        // OnAccept is allowed to close. Keep the object alive until the
        // callback returns, then either reclaim it or arm the first recv.
        Inc(Conn.FOutstanding);
        if Assigned(OnAccept) then OnAccept(Conn);
        Dec(Conn.FOutstanding);
        if Conn.FDead then
          Conn.TryFinalize
        else
          Conn.ArmReceive;
      end
      else
      begin
        Conn.CloseConnectionSocket;
        Conn.Free;
      end;
    end
    else
      WinSock2.closesocket(AcceptedSocket);
  end
  else if AcceptedSocket <> INVALID_SOCKET then
    WinSock2.closesocket(AcceptedSocket);

  if not FStopping then ArmAccept;
end;

procedure TWSIocpTransport.HandleConnectionCompletion(AConn: TWSIocpConn;
  AOverlapped: POverlapped; ABytes: DWORD; ASucceeded: Boolean);
begin
  if AOverlapped = @AConn.FReceiveOverlapped then
  begin
    if not AConn.FDead then
    begin
      if (not ASucceeded) or (ABytes = 0) then
        RemoteClosed(AConn)
      else if Assigned(OnData) then
        OnData(AConn, @AConn.FReceiveBuffer[0], ABytes);
    end;
    Dec(AConn.FOutstanding);
    if AConn.FDead then
      AConn.TryFinalize
    else
      AConn.ArmReceive;
  end
  else if AOverlapped = @AConn.FSendOverlapped then
  begin
    AConn.FSendInFlight := False;
    if not AConn.FDead then
    begin
      if not ASucceeded then
        RemoteClosed(AConn)
      else if Assigned(OnSendReady) then
        OnSendReady(AConn);
    end;
    Dec(AConn.FOutstanding);
    if AConn.FDead then AConn.TryFinalize;
  end;
end;

procedure TWSIocpTransport.WaitAndDispatch(ATimeout: DWORD);
var
  Bytes: DWORD;
  CompletionKey: PtrUInt;
  Overlapped: POverlapped;
  Succeeded: Boolean;
  Conn: TWSIocpConn;
begin
  Bytes := 0;
  CompletionKey := 0;
  Overlapped := nil;
  Succeeded := C_GetQueuedCompletionStatus(FCompletionPort, Bytes,
    CompletionKey, Overlapped, ATimeout);
  if Overlapped = nil then Exit;
  if (CompletionKey = ListenerCompletionKey) and
      (Overlapped = @FAcceptOverlapped) then
  begin
    HandleAcceptCompletion(Succeeded);
    Exit;
  end;
  if (CompletionKey = ListenerCompletionKey) or
      (CompletionKey = WakeCompletionKey) then Exit;
  Conn := TWSIocpConn(Pointer(CompletionKey));
  HandleConnectionCompletion(Conn, Overlapped, Bytes, Succeeded);
end;

procedure TWSIocpTransport.Open;
begin
  if FOpen then Exit;
  FOpen := True;
  ArmAccept;
end;

procedure TWSIocpTransport.Run(ATimeoutMs: Integer);
begin
  FRunning := True;
  if ATimeoutMs < 0 then
    repeat
      WaitAndDispatch(InfiniteWait);
    until not FRunning
  else
    WaitAndDispatch(DWORD(ATimeoutMs));
end;

procedure TWSIocpTransport.Stop;
begin
  FStopping := True;
  FRunning := False;
  if FCompletionPort <> 0 then
    C_PostQueuedCompletionStatus(FCompletionPort, 0,
      WakeCompletionKey, nil);
end;

procedure TWSIocpTransport.Shutdown;
var
  Conn: TWSIocpConn;
  I: Integer;
begin
  if FShutdownDone then Exit;
  FShutdownDone := True;
  FStopping := True;
  FRunning := False;

  if FListenSocket <> INVALID_SOCKET then
  begin
    WinSock2.closesocket(FListenSocket);
    FListenSocket := INVALID_SOCKET;
  end;
  if FAcceptSocket <> INVALID_SOCKET then
  begin
    WinSock2.closesocket(FAcceptSocket);
    FAcceptSocket := INVALID_SOCKET;
  end;

  I := 0;
  while I < FLiveCount do
  begin
    Conn := FLive[I];
    Conn.SubmitClose;
    if (I < FLiveCount) and (FLive[I] = Conn) then Inc(I);
  end;

  while FAcceptPending or (FLiveCount > 0) do
    WaitAndDispatch(InfiniteWait);
  if FCompletionPort <> 0 then
  begin
    CloseHandle(FCompletionPort);
    FCompletionPort := 0;
  end;
end;

{$endif}

end.
