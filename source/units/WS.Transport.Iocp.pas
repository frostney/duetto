unit WS.Transport.Iocp;

// Windows transport: one IOCP thread implementing the WS.Transport
// completion contract. AcceptEx, WSARecv, and WSASend are always armed
// overlapped; every callback and deferred free runs on the thread in
// Run — with one documented exception: a DROPPED OnPost (AConn = nil)
// fires wherever the drop was noticed, which is the posting thread when
// SubmitPost finds the queue stopped, or the Shutdown thread when
// Shutdown reclaims what was still pending. See TWSTransportPostEvent.

{$I Shared.inc}

interface

{$ifdef WINDOWS}

uses
  SysUtils,
  Windows,

  WinSock2,
  WS.Transport,
  WS.Transport.PostQueue;

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
    FSendPosted: DWORD;        // bytes posted in the current WSASend
    FSendOffset: DWORD;        // bytes already completed of that post
    FDead: Boolean;
    FCloseRequested: Boolean;  // SubmitClose while a send is in flight
    FSentAny: Boolean;         // a WSASend completed; peer earned a FIN
    FFinSent: Boolean;         // graceful close begun; recv drains to EOF
    procedure ArmReceive;
    procedure CloseConnectionSocket;
    procedure BeginGracefulClose;
    procedure HardClose;
    function ResumeSend: Boolean;
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
    FPosts: TWSPostQueue;      // cross-thread SubmitPost hand-off
    procedure ArmAccept;
    procedure Track(AConn: TWSIocpConn);
    procedure Untrack(AConn: TWSIocpConn);
    procedure RemoteClosed(AConn: TWSIocpConn);
    procedure HandleAcceptCompletion(ASucceeded: Boolean);
    procedure HandleConnectionCompletion(AConn: TWSIocpConn;
      AOverlapped: POverlapped; ABytes: DWORD; ASucceeded: Boolean);
    procedure WaitAndDispatch(ATimeout: DWORD);
    procedure DeliverPosts(AChain: PWSPostNode; ADropped: Boolean);
    procedure SweepPosts;
  public
    constructor Create(APort: Word; const ATls: TWSTransportTls);
    destructor Destroy; override;
    procedure Run(ATimeoutMs: Integer = -1); override;
    procedure Stop; override;
    procedure Open; override;
    procedure Shutdown; override;
    procedure SubmitPost(AConnId: NativeUInt; AData: Pointer); override;
  end;

{$endif}

implementation

{$ifdef WINDOWS}

const
  WSA_FLAG_OVERLAPPED = $00000001;
  SO_UPDATE_ACCEPT_CONTEXT = $700B;
  WinErrorIoPending = 997;
  SdSend = 1; // shutdown(): SD_SEND
  SO_EXCLUSIVEADDRUSE = Integer(not DWORD(SO_REUSEADDR));
  InfiniteWait = DWORD($FFFFFFFF);
  ListenerCompletionKey = PtrUInt(1);
  WakeCompletionKey = PtrUInt(2);
  PostCompletionKey = PtrUInt(3); // SubmitPost wake: drain FPosts
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
function C_shutdown(ASocket: TSocket; AHow: Integer): Integer; stdcall;
  external WINSOCK2_DLL name 'shutdown';
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

// Re-post the unsent tail of the current send buffer. True = the
// overlapped operation is armed again (the completed op's pin carries
// over); False = the connection died trying.
function TWSIocpConn.ResumeSend: Boolean;
var
  Buffer: TWSIocpBuffer;
begin
  Result := True;
  FillChar(FSendOverlapped, SizeOf(FSendOverlapped), 0);
  Buffer.Len := FSendPosted - FSendOffset;
  Buffer.Buf := PAnsiChar(@FSendBuffer[FSendOffset]);
  if C_WSASend(FSocket, @Buffer, 1, nil, 0,
      @FSendOverlapped, nil) = SOCKET_ERROR then
    if WSAGetLastError <> WinErrorIoPending then
    begin
      FDead := True;
      CloseConnectionSocket;
      Result := False;
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
  FSendPosted := Accepted;
  FSendOffset := 0;
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

procedure TWSIocpConn.HardClose;
begin
  if not FDead then
  begin
    FDead := True;
    CloseConnectionSocket;
  end;
  TryFinalize;
end;

// Final bytes are flushed; put a FIN on the wire instead of resetting.
// closesocket with an armed overlapped WSARecv resets the connection on
// WinSock — the peer sees RST, and a Windows peer then DISCARDS
// buffered-but-unread data, losing the very bytes the deferred close
// existed to deliver (the win64 CI plain-request battery caught exactly
// this). shutdown(SD_SEND) sends the FIN while the armed receive stays
// outstanding; the peer's own close completes that receive, and the
// zero-byte/error completion performs the real teardown via
// RemoteClosed. A peer that never closes holds the connection until
// Shutdown's sweep hard-closes it — bounded, and only reachable by
// peers that already received a complete reply.
procedure TWSIocpConn.BeginGracefulClose;
begin
  if FDead or FFinSent then Exit;
  FFinSent := True;
  C_shutdown(FSocket, SdSend);
end;

procedure TWSIocpConn.SubmitClose;
begin
  // A send still in flight carries the final bytes (typically a close
  // frame or handshake rejection) — closesocket would cancel the
  // overlapped WSASend. Defer; the send completion finishes the close.
  if FSendInFlight and (not FDead) then
  begin
    FCloseRequested := True;
    Exit;
  end;
  // Peers that were sent a reply get a graceful FIN (see
  // BeginGracefulClose); peers that never earned one — a handshake
  // flooder, a parse failure before any response — are reset, which
  // also frees their connection immediately.
  if (not FDead) and FSentAny then
    BeginGracefulClose
  else
    HardClose;
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
  FPosts := TWSPostQueue.Create;
  if ATls.Enabled then
    raise Exception.Create(
      'iocp transport has no TLS yet; tracked as duetto#22 (upstream ' +
      'contracts shipped in lwpt 0.5.0; duetto wiring pending). Run ' +
      'behind a TLS-terminating proxy');

  if WSAStartup($0202, Data) <> 0 then
    raise Exception.Create('WSAStartup failed');
  FWinSockStarted := True;

  FListenSocket := C_WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
    nil, 0, WSA_FLAG_OVERLAPPED);
  if FListenSocket = INVALID_SOCKET then
    raise Exception.CreateFmt('WSASocketW() failed (%d)', [WSAGetLastError]);
  // Windows SO_REUSEADDR permits hostile duplicate binds (unlike its
  // POSIX use); exclusive binding is the hardened server default.
  One := 1;
  WinSock2.setsockopt(FListenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
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
  FPosts.Free;
  if FAcceptSocket <> INVALID_SOCKET then
    WinSock2.closesocket(FAcceptSocket);
  if FListenSocket <> INVALID_SOCKET then
    WinSock2.closesocket(FListenSocket);
  // The one place the port is closed (see Shutdown): Shutdown is
  // idempotent and any-thread, Destroy is the single-owner end of life.
  if FCompletionPort <> 0 then
  begin
    CloseHandle(FCompletionPort);
    FCompletionPort := 0;
  end;
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
  // Released in a finally: a raising OnClosed would otherwise strand
  // the pin, TryFinalize would never fire, and Shutdown's drain would
  // spin on FLiveCount forever.
  Inc(AConn.FOutstanding);
  try
    if Assigned(OnClosed) then OnClosed(AConn);
  finally
    Dec(AConn.FOutstanding);
    AConn.TryFinalize;
  end;
end;

procedure TWSIocpTransport.ArmAccept;
var
  Bytes: DWORD;
  Err: Integer;
begin
  if FStopping or FAcceptPending then Exit;
  repeat
    FAcceptSocket := C_WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
      nil, 0, WSA_FLAG_OVERLAPPED);
    if FAcceptSocket = INVALID_SOCKET then
      raise Exception.Create('accept WSASocketW() failed');
    FillChar(FAcceptOverlapped, SizeOf(FAcceptOverlapped), 0);
    FillChar(FAcceptBuffer, SizeOf(FAcceptBuffer), 0);
    Bytes := 0;
    if C_AcceptEx(FListenSocket, FAcceptSocket, @FAcceptBuffer[0], 0,
        AcceptAddressLength, AcceptAddressLength, @Bytes,
        @FAcceptOverlapped) then Break;
    Err := WSAGetLastError;
    if Err = WinErrorIoPending then Break;
    // The backlog head was reset before acceptance — a documented
    // transient (AcceptEx fails synchronously with WSAECONNRESET or
    // WSAECONNABORTED; MSDN says retry). Raising here would unwind the
    // completion thread and silently stop the listener for good: the
    // kernel backlog keeps completing TCP handshakes no one will ever
    // read. Retire this accept socket and re-arm for the next backlog
    // entry; anything else stays fatal.
    WinSock2.closesocket(FAcceptSocket);
    FAcceptSocket := INVALID_SOCKET;
    if (Err <> WSAECONNRESET) and (Err <> WSAECONNABORTED) then
      raise Exception.CreateFmt('AcceptEx() failed (%d)', [Err]);
  until False;
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
  // The re-arm lives in the outer finally: a raising OnAccept (or a
  // raise out of the pin's own finally) must not leave the listener
  // permanently unarmed — a host that catches the exception and
  // re-enters Run would otherwise serve nothing while the kernel
  // backlog keeps completing handshakes nobody reads.
  try
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
        // callback returns, then either reclaim it or arm the first
        // recv. The tail runs in a finally: a raising OnAccept must not
        // strand the pin, or TryFinalize never fires and Shutdown's
        // drain spins forever.
        Inc(Conn.FOutstanding);
        try
          if Assigned(OnAccept) then OnAccept(Conn);
        finally
          Dec(Conn.FOutstanding);
          if Conn.FDead then
            Conn.TryFinalize
          else
            Conn.ArmReceive;
        end;
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
  finally
    if not FStopping then ArmAccept;
  end;
end;

procedure TWSIocpTransport.HandleConnectionCompletion(AConn: TWSIocpConn;
  AOverlapped: POverlapped; ABytes: DWORD; ASucceeded: Boolean);
begin
  if AOverlapped = @AConn.FReceiveOverlapped then
  begin
    // The completed WSARecv's pin is ours to release. In a finally: a
    // raising OnData (or OnClosed, underneath RemoteClosed) must not
    // strand it — TryFinalize would never fire and Shutdown's drain
    // would spin forever.
    try
      if not AConn.FDead then
      begin
        if (not ASucceeded) or (ABytes = 0) then
          RemoteClosed(AConn)
        else if Assigned(OnData) then
          OnData(AConn, @AConn.FReceiveBuffer[0], ABytes);
      end;
    finally
      Dec(AConn.FOutstanding);
      if AConn.FDead then
        AConn.TryFinalize
      else
        AConn.ArmReceive;
    end;
  end
  else if AOverlapped = @AConn.FSendOverlapped then
  begin
    if ASucceeded and (not AConn.FDead) then
    begin
      AConn.FSentAny := True; // this peer has earned a graceful FIN
      // A stream WSASend may complete short under memory pressure; the
      // caller was told the full accepted count, so the tail must go
      // out before anything else touches the send buffer.
      Inc(AConn.FSendOffset, ABytes);
      if AConn.FSendOffset < AConn.FSendPosted then
      begin
        if AConn.ResumeSend then Exit;
        // resume failed: fall through to the dead path below
      end;
    end;
    AConn.FSendInFlight := False;
    // Only from here is the completed WSASend's pin ours to release —
    // the ResumeSend path above exits with it deliberately carried over
    // to the re-armed operation, so the guarded region starts below it.
    // Everything from here on can reach user code, and a raising
    // handler must not strand the pin: TryFinalize would never fire and
    // Shutdown's drain would spin forever.
    try
      if not AConn.FDead then
      begin
        if not ASucceeded then
          RemoteClosed(AConn)
        else if AConn.FCloseRequested then
          // The deferred close's final bytes just went out; FIN, don't
          // reset (see BeginGracefulClose). The armed receive drains to
          // the peer's EOF, whose completion tears the connection down.
          AConn.BeginGracefulClose
        else if Assigned(OnSendReady) then
          OnSendReady(AConn);
      end
      else if AConn.FCloseRequested then
        AConn.HardClose;
    finally
      Dec(AConn.FOutstanding);
      if AConn.FDead then AConn.TryFinalize;
    end;
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
  // Post wakes carry a nil overlapped, so this check precedes the nil
  // guard. (On timeout GetQueuedCompletionStatus leaves the key
  // untouched — it stays the 0 initialized above.)
  if CompletionKey = PostCompletionKey then
  begin
    DeliverPosts(FPosts.Drain, False);
    Exit;
  end;
  // Stop's wake is a WakeCompletionKey with a nil overlapped and is
  // consumed right here, together with a timeout's empty return —
  // there is nothing to dispatch either way, and Run re-tests FRunning.
  // (That is why no WakeCompletionKey test appears below: it could
  // never be reached.)
  if Overlapped = nil then Exit;
  if (CompletionKey = ListenerCompletionKey) and
      (Overlapped = @FAcceptOverlapped) then
  begin
    HandleAcceptCompletion(Succeeded);
    Exit;
  end;
  if CompletionKey = ListenerCompletionKey then Exit;
  Conn := TWSIocpConn(Pointer(CompletionKey));
  HandleConnectionCompletion(Conn, Overlapped, Bytes, Succeeded);
end;

// Completion-thread only (or Shutdown, with Run returned): serialized
// with every other completion by construction. ADropped skips the conn
// lookup so shutdown reclaims envelopes without touching connections.
procedure TWSIocpTransport.DeliverPosts(AChain: PWSPostNode;
  ADropped: Boolean);
var
  Node, Next: PWSPostNode;
  Conn: TWSIocpConn;
  I: Integer;
begin
  Node := AChain;
  try
    while Node <> nil do
    begin
      Conn := nil;
      if not ADropped then
        // Posts are cold path, a scan is fine. Re-scanned per node: the
        // previous OnPost may have torn any connection down. FDead conns
        // are pending finalize — the session has let go of them.
        for I := 0 to FLiveCount - 1 do
          if FLive[I].Id = Node^.ConnId then
          begin
            if not FLive[I].FDead then Conn := FLive[I];
            Break;
          end;
      Next := Node^.Next;
      try
        if Conn <> nil then
        begin
          // The posted proc may close the connection; pin the object
          // across the callback like the accept path does. The pin is
          // released even if the proc raises — a leaked pin would keep
          // FOutstanding above zero and hang Shutdown's drain forever.
          Inc(Conn.FOutstanding);
          try
            if Assigned(OnPost) then OnPost(Conn, Node^.Data);
          finally
            Dec(Conn.FOutstanding);
            if Conn.FDead then Conn.TryFinalize;
          end;
        end
        else if Assigned(OnPost) then
          OnPost(nil, Node^.Data);
      finally
        Dispose(Node);
        Node := Next;
      end;
    end;
  finally
    // A posted proc that raises unwinds Run like any other handler,
    // but the rest of the chain must not leak: hand each envelope back
    // as dropped (nil conn frees it in the session) and reclaim nodes.
    while Node <> nil do
    begin
      Next := Node^.Next;
      if Assigned(OnPost) then OnPost(nil, Node^.Data);
      Dispose(Node);
      Node := Next;
    end;
  end;
end;

procedure TWSIocpTransport.SubmitPost(AConnId: NativeUInt; AData: Pointer);
begin
  if not FPosts.Push(AConnId, AData) then
  begin
    // Stopped: dropped on the calling thread.
    if Assigned(OnPost) then OnPost(nil, AData);
    Exit;
  end;
  // Wake the completion-port thread the same way Stop does. Reading
  // FCompletionPort unsynchronized is sound because the handle now
  // outlives Shutdown — it is closed in Destroy, not here — so a Push
  // that won the race against Shutdown still posts to a valid handle
  // (its node was already reclaimed by the shutdown drain, so the wake
  // just dequeues into an empty drain). Posting into Destroy itself
  // remains UB by contract: the caller must have stopped posting before
  // it frees the transport.
  if FCompletionPort <> 0 then
    // Quota exhaustion is the documented transient failure mode here;
    // one retry clears it in practice, and Run's per-round HasPending
    // sweep is the backstop when it does not.
    if not C_PostQueuedCompletionStatus(FCompletionPort, 0,
        PostCompletionKey, nil) then
      C_PostQueuedCompletionStatus(FCompletionPort, 0,
        PostCompletionKey, nil);
end;

procedure TWSIocpTransport.Open;
begin
  if FOpen then Exit;
  FOpen := True;
  ArmAccept;
end;

// Wake-independent backstop, once per completion round: a post whose
// PostQueuedCompletionStatus wake was lost would otherwise sit in the
// queue until Shutdown. The dirty HasPending read costs one predictable
// branch per dispatched completion, never one per connection.
// Not absolute: an idle Run(-1) thread parked in GetQueuedCompletionStatus
// produces no completion round, so a post whose PQCS wake failed twice
// waits for traffic or Shutdown. The sweep covers the realistic case —
// wake lost or post landing behind a drain on a live server.
procedure TWSIocpTransport.SweepPosts;
begin
  if FPosts.HasPending then DeliverPosts(FPosts.Drain, False);
end;

procedure TWSIocpTransport.Run(ATimeoutMs: Integer);
begin
  if FStopping then Exit;
  FRunning := True;
  if ATimeoutMs < 0 then
    repeat
      WaitAndDispatch(InfiniteWait);
      SweepPosts;
    until not FRunning
  else
  begin
    WaitAndDispatch(DWORD(ATimeoutMs));
    SweepPosts;
  end;
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

  // Stop the post queue first: pending posts are delivered once as
  // dropped (AConn = nil) so the session reclaims their envelopes, and
  // any SubmitPost racing us is refused at Push and dropped by its own
  // caller thread. Stale post wakes still sitting in the port dequeue
  // into an empty drain (harmless) or are discarded when Destroy closes
  // the port.
  DeliverPosts(FPosts.Stop, True);

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
    Conn.HardClose; // abort in-flight I/O; the drain below reaps
    if (I < FLiveCount) and (FLive[I] = Conn) then Inc(I);
  end;

  while FAcceptPending or (FLiveCount > 0) do
    WaitAndDispatch(InfiniteWait);
  // The port handle is deliberately NOT closed here. SubmitPost reads
  // FCompletionPort without synchronization, and closing it in a
  // quiesce that any thread may call would put a straggler
  // PostQueuedCompletionStatus on a freed (or recycled) handle. Destroy
  // closes it instead — by then the caller has, by contract, stopped
  // using the transport altogether.
end;

{$endif}

end.
