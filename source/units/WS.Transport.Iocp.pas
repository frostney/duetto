unit WS.Transport.Iocp;

// Windows transport: one IOCP thread implementing the WS.Transport
// completion contract. AcceptEx, WSARecv, and WSASend are always armed
// overlapped; every callback and deferred free runs on the thread in
// Run — with one documented exception: a DROPPED OnPost (AConn = nil)
// fires wherever the drop was noticed, which is the posting thread when
// SubmitPost finds the queue stopped, or the Shutdown thread when
// Shutdown reclaims what was still pending. See TWSTransportPostEvent.
//
// Server TLS (duetto#22) rides WS.Transport.TlsServer — the same
// platform-neutral session unit the epoll transport drives, so both
// fd-owning backends share one implementation of lwpt's flow-control
// contract and stay pure byte movers. This transport keeps the
// syscalls: it owns the socket, the completion port and the two
// reactor-owned guards (handshake deadline, inbound pre-handshake
// budget); the session unit owns every TLS state transition, the carry
// buffer, the watermark policy and all flow accounting. The two meet
// through guarded `if FTls <> nil` forks, so a plaintext listener runs
// the same code, with the same work per completion, as it did before
// TLS existed.
//
// The TLS additions to the completion loop proper are:
//   - a bounded GetQueuedCompletionStatus timeout while any connection
//     carries a deadline (handshake pending, or a graceful close
//     draining), so a peer that goes silent still gets swept;
//   - the next WSARecv suppressed while lwpt reports encrypted-input
//     backpressure, re-armed on lwpt's own low-water hysteresis — the
//     Windows counterpart of the epoll reactor dropping EPOLLIN;
//   - a deferred close: close_notify has to reach the socket before the
//     FIN, which can outlive the SubmitClose that asked for it.

{$I Shared.inc}

interface

{$ifdef WINDOWS}

uses
  SysUtils,
  Windows,

  TransportSecurity,
  WinSock2,
  WS.Transport,
  WS.Transport.PostQueue,
  WS.Transport.TlsServer;

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
    // --- TLS only; all nil/False on a plaintext listener --------------
    FTls: TWSTlsServerSession;
    // No WSARecv is outstanding and none may be armed until lwpt's
    // encrypted-input low watermark clears. Exactly one receive is ever
    // in flight, so this single token is what the arm paths agree on.
    FRecvSuppressed: Boolean;
    FInPump: Boolean;          // inside a TLS pump; teardown defers
    FFreeDeferred: Boolean;    // SubmitClose landed mid-pump
    FClosing: Boolean;         // graceful close draining; no callbacks
    // A SubmitSend went short: the session layer is holding output and
    // waiting for the OnSendReady the transport contract promises. It
    // is tracked separately from what the TLS engine owes the WIRE,
    // because the two clear at different moments — lwpt's ciphertext
    // queue can empty in the very round that leaves the caller holding
    // output, and a send completion that skipped the callback there
    // strands the connection with no completion left to restart it.
    FSendReadyOwed: Boolean;
    FTimed: Boolean;           // counted in the transport's deadline sweep
    FDeadline: QWord;          // close-drain deadline (monotonic)
    procedure ArmReceive;
    procedure CloseConnectionSocket;
    procedure BeginGracefulClose;
    procedure HardClose;
    function RawSend(P: PByte; ALen: NativeInt): NativeInt;
    function ResumeSend: Boolean;
    procedure TryFinalize;
    procedure SetTimed(AValue: Boolean);
    // TWSTlsServerSession callbacks.
    function TlsPlaintext(P: PByte; ALen: NativeInt): Boolean;
    function TlsCiphertext(P: PByte; ALen: NativeInt): NativeInt;
    function TlsSubmitSend(P: PByte; ALen: NativeInt): NativeInt;
    function TlsIngest(P: PByte; ALen: NativeInt): TWSTlsIngestResult;
    procedure ArmTlsReceive;
    procedure ResumeTlsReceive;
    procedure BeginTlsClose;
    procedure StepTlsClose;
    procedure RunDeferredClose;
  public
    destructor Destroy; override;
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
    // TLS: one context for the listener's whole life, nil when off.
    FTlsContext: TTransportSecurityServerContext;
    FTlsPolicy: TWSTlsPolicy;
    FTimedCount: Integer;      // connections carrying a live deadline
    procedure ArmAccept;
    procedure Track(AConn: TWSIocpConn);
    procedure Untrack(AConn: TWSIocpConn);
    procedure RemoteClosed(AConn: TWSIocpConn);
    procedure HandleAcceptCompletion(ASucceeded: Boolean);
    procedure HandleConnectionCompletion(AConn: TWSIocpConn;
      AOverlapped: POverlapped; ABytes: DWORD; ASucceeded: Boolean);
    procedure HandleReceivedTls(AConn: TWSIocpConn; ABytes: DWORD);
    procedure HandleSendCompletionTls(AConn: TWSIocpConn);
    procedure SweepTlsDeadlines;
    function DeadlineBoundedWait(ATimeout: DWORD): DWORD;
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
  // Granularity of the TLS deadline sweep. Only ever shortens a wait
  // that would otherwise park, and only while at least one connection
  // carries a deadline — a plaintext listener never sees it.
  TlsDeadlinePollMs = 100;

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

destructor TWSIocpConn.Destroy;
begin
  SetTimed(False);
  // Frees the lwpt session too (its destructor aborts); every teardown
  // path funnels here, so no branch can leak an OpenSSL session.
  FTls.Free;
  inherited;
end;

procedure TWSIocpConn.CloseConnectionSocket;
begin
  if FSocket = INVALID_SOCKET then Exit;
  WinSock2.closesocket(FSocket);
  FSocket := INVALID_SOCKET;
end;

procedure TWSIocpConn.SetTimed(AValue: Boolean);
begin
  if FTimed = AValue then Exit;
  FTimed := AValue;
  if AValue then
    Inc(FTransport.FTimedCount)
  else
    Dec(FTransport.FTimedCount);
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

// Copy-on-send socket write, shared by the plaintext send path and the
// TLS ciphertext egress. Bytes taken (short is normal — the completion
// brings the caller back), 0 while a send is already in flight, -1 when
// the connection is dead. The signature is TWSTlsCiphertextEvent's by
// construction, so the session unit consumes exactly what the wire took.
function TWSIocpConn.RawSend(P: PByte; ALen: NativeInt): NativeInt;
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

function TWSIocpConn.SubmitSend(P: PByte; ALen: NativeInt): NativeInt;
begin
  if FDead then Exit(-1);
  // The one TLS fork on the send path: a plaintext listener pays a
  // single never-taken branch.
  if FTls <> nil then Exit(TlsSubmitSend(P, ALen));
  Result := RawSend(P, ALen);
end;

procedure TWSIocpConn.HardClose;
begin
  if not FDead then
  begin
    FDead := True;
    // No clock left to run: a dead connection must not be re-swept
    // while its pins drain.
    SetTimed(False);
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
  // Mid-pump: the plaintext delivery that triggered this is still on the
  // stack, and the session's frame loop above it may still parse
  // pipelined frames out of the buffer we would free. Defer to the
  // pump's unwind — the same rule WS.Server's own FInDelivery guard
  // follows, and the caller's contract (drop every reference, expect no
  // further completions) already covers it.
  if FInPump then
  begin
    FFreeDeferred := True;
    Exit;
  end;
  // A send still in flight carries the final bytes (typically a close
  // frame or handshake rejection) — closesocket would cancel the
  // overlapped WSASend. Defer; the send completion finishes the close.
  if FSendInFlight and (not FDead) then
  begin
    FCloseRequested := True;
    Exit;
  end;
  // An activated TLS session owes the peer close_notify before FIN;
  // that can outlive this call when the socket is backed up.
  if (FTls <> nil) and (not FDead) and (not FClosing) and
    FTls.HandshakeDone and (not FTls.Dead) then
  begin
    BeginTlsClose;
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

{ TWSIocpConn — TLS }

// Plaintext sink. False tells the pump to stop: the delivery tore this
// connection down and the session unit must not touch anything else.
function TWSIocpConn.TlsPlaintext(P: PByte; ALen: NativeInt): Boolean;
begin
  if Assigned(FTransport.OnData) then FTransport.OnData(Self, P, ALen);
  Result := (not FFreeDeferred) and (not FDead);
end;

// Ciphertext egress. The session unit consumes exactly what this
// returns, so a short take costs nothing but a later send completion.
function TWSIocpConn.TlsCiphertext(P: PByte; ALen: NativeInt): NativeInt;
begin
  Result := RawSend(P, ALen);
end;

function TWSIocpConn.TlsIngest(P: PByte;
  ALen: NativeInt): TWSTlsIngestResult;
begin
  FInPump := True;
  try
    Result := FTls.Ingest(P, ALen);
  finally
    FInPump := False;
  end;
  if FFreeDeferred then Exit; // teardown pending; do not touch the clock
  // The handshake clock stops the moment the session activates; from
  // then on only a close drain puts this connection back in the sweep.
  if FTimed and (not FClosing) and FTls.HandshakeDone then SetTimed(False);
end;

function TWSIocpConn.TlsSubmitSend(P: PByte; ALen: NativeInt): NativeInt;
begin
  Result := FTls.Encrypt(P, ALen);
  if Result < 0 then
  begin
    FDead := True;
    SetTimed(False);
    CloseConnectionSocket;
    Exit(-1);
  end;
  // A short accept owes the caller an OnSendReady whatever caused it —
  // a send already in flight, or the encrypted-output capacity running
  // out while the socket stayed writable. Either way lwpt had
  // ciphertext to hand over, so a WSASend is outstanding and its
  // completion is what pays the debt.
  if Result < ALen then FSendReadyOwed := True;
end;

// Arm the next receive unless lwpt's encrypted input is still
// backpressured. Exactly one WSARecv may ever be outstanding, so every
// arm on a TLS connection funnels here and FRecvSuppressed is the single
// token for "none is armed, and none may be until MayResume".
//
// Suppressing leaves a live connection with NO outstanding operation,
// which is safe on both counts that matter here. Finalization: the pin
// count guards against use-after-free, not against liveness, and
// TryFinalize only ever frees a connection already marked dead — so a
// suppressed connection at zero pins is reaped immediately by
// Shutdown's HardClose sweep rather than being missed by it. Liveness:
// backpressure the pump could not clear means lwpt still holds
// ciphertext the socket has not taken, so a WSASend is in flight and
// its completion re-drives the pump and calls ResumeTlsReceive.
procedure TWSIocpConn.ArmTlsReceive;
begin
  if FDead then Exit;
  // Draining close_notify: nothing the peer says can matter now, but a
  // receive stays armed so the peer's EOF still completes and reaps
  // this connection — the same role it plays in the plaintext graceful
  // close. Its bytes are dropped on the floor.
  if FClosing or FTls.MayResume then
  begin
    FRecvSuppressed := False;
    ArmReceive;
  end
  else
    FRecvSuppressed := True;
end;

// Called after any pump that may have cleared the backpressure. Only
// the holder of the suppression token arms, so a receive is never
// doubled.
procedure TWSIocpConn.ResumeTlsReceive;
begin
  if FRecvSuppressed then ArmTlsReceive;
end;

procedure TWSIocpConn.BeginTlsClose;
begin
  FClosing := True;
  FCloseRequested := False;
  UserData := nil;
  FDeadline := SysUtils.GetTickCount64 +
    QWord(FTransport.FTlsPolicy.HandshakeDeadlineMs);
  SetTimed(True);
  // A suppressed connection has no receive to notice the peer's EOF
  // with; the drain needs one. Inside a receive completion the token
  // reads False (the completion's own tail is the single place that
  // re-arms), so this cannot double an armed operation.
  ResumeTlsReceive;
  // A receive that failed to arm reaps the connection through
  // RemoteClosed; the caller's pin keeps the object alive to here, but
  // there is nothing left to drain.
  if FDead then Exit;
  StepTlsClose;
end;

// One step of the close_notify drain. Runs from BeginTlsClose, from a
// send completion, and from the deadline sweep's bound.
procedure TWSIocpConn.StepTlsClose;
begin
  if FTls.DrainClose then
  begin
    // Nothing left to write. A session that died on the way out has no
    // orderly shutdown to offer, so it is reset; one that flushed its
    // close_notify earns the FIN — the peer must be able to READ what
    // it was just sent, and closesocket with an armed overlapped
    // receive resets instead (see BeginGracefulClose). The armed
    // receive then drains to the peer's EOF, and that completion
    // finalizes the connection — with the close-drain deadline left
    // running, so a peer that reads the alert and then never closes is
    // reaped by the sweep instead of holding the socket until Shutdown.
    if FTls.Dead then
      HardClose
    else
      BeginGracefulClose;
    Exit;
  end;
  // Still bytes to push. DrainClose already offered everything it had
  // to the socket, so a WSASend is outstanding and its completion steps
  // us again; the close-drain deadline bounds a peer that stopped
  // reading altogether.
end;

// A pump deferred its own teardown; it has now unwound.
procedure TWSIocpConn.RunDeferredClose;
begin
  FFreeDeferred := False;
  SubmitClose;
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
  // Resolve and validate the whole TLS policy, and load the identity,
  // before the listener takes a port: a bad watermark or an unreadable
  // PKCS#12 must fail the constructor, not the first handshake.
  if ATls.Enabled then
  begin
    FTlsPolicy := WSTlsResolvePolicy(ATls);
    FTlsContext := WSTlsCreateServerContext(ATls, FTlsPolicy);
  end;

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
  // After Shutdown no connection holds a session against it any more.
  if FTlsContext <> nil then
    CloseTransportSecurityServerContext(FTlsContext);
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
  // A connection draining its close_notify has already been handed back
  // to the transport — the session dropped its reference and UserData
  // is nil — so it is reaped silently rather than announced a second
  // time. The single guard covers every caller: both completion paths,
  // the deadline sweep, and a receive that failed to arm.
  if AConn.FClosing then
  begin
    AConn.HardClose;
    Exit;
  end;
  AConn.FDead := True;
  // Out of the deadline sweep before any callback: a dead connection
  // has no clock left to run. The lwpt session is released when the
  // object is finalized (its destructor aborts) — the one funnel.
  AConn.SetTimed(False);
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
  TlsFailed: Boolean;
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
        TlsFailed := False;
        if FTlsContext <> nil then
          try
            Conn.FTls := TWSTlsServerSession.Create(FTlsContext, FTlsPolicy,
              Conn.TlsPlaintext, Conn.TlsCiphertext);
          except
            // A session lwpt refuses is this connection's problem, not
            // the listener's: drop it and keep accepting.
            TlsFailed := True;
          end;
        if TlsFailed then
        begin
          Conn.CloseConnectionSocket;
          Conn.Free;
        end
        else
        begin
          Track(Conn);
          // The handshake clock starts at accept and is enforced by
          // this transport, not by lwpt: a peer that connects and says
          // nothing is exactly the case no TLS engine can time out.
          if Conn.FTls <> nil then Conn.SetTimed(True);
          // OnAccept is allowed to close. Keep the object alive until
          // the callback returns, then either reclaim it or arm the
          // first recv. The tail runs in a finally: a raising OnAccept
          // must not strand the pin, or TryFinalize never fires and
          // Shutdown's drain spins forever.
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
          // A connection draining its close_notify is reaped silently
          // here — RemoteClosed owns that distinction.
          RemoteClosed(AConn)
        // The one TLS fork on the receive path: a plaintext listener
        // pays a single never-taken branch per completion.
        else if AConn.FTls <> nil then
          HandleReceivedTls(AConn, ABytes)
        else if Assigned(OnData) then
          OnData(AConn, @AConn.FReceiveBuffer[0], ABytes);
      end;
    finally
      Dec(AConn.FOutstanding);
      if AConn.FDead then
        AConn.TryFinalize
      else if AConn.FTls <> nil then
        AConn.ArmTlsReceive
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
        // The one TLS fork on the send path: a plaintext listener pays
        // a single never-taken branch per completion.
        else if AConn.FTls <> nil then
          HandleSendCompletionTls(AConn)
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

// The TLS twin of the OnData delivery. Same completed WSARecv, same
// buffer; the difference is that bytes go to the TLS session instead of
// straight to OnData (plaintext surfaces through TlsPlaintext), and
// that the completion's tail may decline to re-arm while lwpt reports
// encrypted-input backpressure.
procedure TWSIocpTransport.HandleReceivedTls(AConn: TWSIocpConn;
  ABytes: DWORD);
begin
  // Draining close_notify: no session callbacks are left to make, and
  // nothing the peer says now can matter. Its bytes are dropped and the
  // receive is re-armed only so the EOF behind them still reaps us.
  if AConn.FClosing then Exit;
  if AConn.TlsIngest(@AConn.FReceiveBuffer[0], NativeInt(ABytes)) =
    wtiFailed then
  begin
    // A plaintext delivery may have dropped this connection first; that
    // free waited for the pump to unwind, which it just did.
    if AConn.FFreeDeferred then
      AConn.RunDeferredClose
    else
      RemoteClosed(AConn);
    Exit;
  end;
  if AConn.FFreeDeferred then AConn.RunDeferredClose;
end;

// A TLS connection's send completion is ciphertext leaving the wire, so
// it drives the engine before it touches the session layer: the pump
// flushes whatever lwpt still has queued (starting the next WSASend),
// resumes a write lwpt could not finish, drives a pending handshake and
// decrypts what the input buffer holds — which is also what frees
// encrypted-input space and lets a suppressed receive re-arm.
procedure TWSIocpTransport.HandleSendCompletionTls(AConn: TWSIocpConn);
begin
  if AConn.FClosing then
  begin
    AConn.StepTlsClose;
    Exit;
  end;
  if AConn.TlsIngest(nil, 0) = wtiFailed then
  begin
    if AConn.FFreeDeferred then
      AConn.RunDeferredClose
    else
      RemoteClosed(AConn);
    Exit;
  end;
  if AConn.FFreeDeferred then
  begin
    AConn.RunDeferredClose;
    Exit;
  end;
  if AConn.FDead then Exit;
  if AConn.FCloseRequested then
  begin
    // A SubmitClose that landed while this send was in flight. Its
    // final bytes are out; an activated session still owes close_notify
    // before the FIN, anything else is the plaintext path.
    if AConn.FTls.HandshakeDone and (not AConn.FTls.Dead) then
      AConn.BeginTlsClose
    else
    begin
      AConn.FCloseRequested := False;
      AConn.BeginGracefulClose;
    end;
    Exit;
  end;
  // Hand the session layer the re-offer it is owed. Skipped only while
  // the engine still owes the WIRE and the caller is owed nothing — a
  // further completion is already on its way in that case. The two are
  // tracked apart because they clear at different moments: lwpt's queue
  // can empty in the very round that leaves the caller holding output,
  // and a completion that skipped the callback there would strand the
  // connection with nothing left to restart it (the epoll reactor hit
  // exactly this, as a wedged 512 KiB echo).
  if AConn.FSendReadyOwed or (not AConn.FTls.NeedsWritable) then
  begin
    // Pay the debt before the callback, so a send inside it that goes
    // short can record a fresh one.
    AConn.FSendReadyOwed := False;
    // The callback runs outside any pump, so a drop inside it takes the
    // immediate path — and the completion's own pin keeps the object
    // alive until the finally, so testing FDead here is enough.
    if Assigned(OnSendReady) then OnSendReady(AConn);
    if AConn.FDead or AConn.FClosing then Exit;
  end;
  AConn.ResumeTlsReceive;
end;

// Reactor-owned deadlines, swept once per completion round and only
// while at least one connection carries one. Two kinds:
//   - handshake pending: a peer that connected and then went quiet (or
//     trickles just enough to look alive) is aborted;
//   - graceful close draining: a peer that stopped reading must not pin
//     the socket forever waiting for its close_notify to fit.
procedure TWSIocpTransport.SweepTlsDeadlines;
var
  I: Integer;
  NowTick: QWord;
  Conn: TWSIocpConn;
begin
  NowTick := SysUtils.GetTickCount64;
  I := 0;
  while I < FLiveCount do
  begin
    Conn := FLive[I];
    if (Conn = nil) or (not Conn.FTimed) or Conn.FDead then
    begin
      Inc(I);
      Continue;
    end;
    if Conn.FClosing then
    begin
      if NowTick >= Conn.FDeadline then Conn.HardClose;
    end
    else if Conn.FTls.DeadlineExpired then
      RemoteClosed(Conn);
    // Untrack swaps the last entry into this slot, so an index that
    // still holds the same object is the only one safe to advance past.
    if (I < FLiveCount) and (FLive[I] = Conn) then Inc(I);
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
        // are pending finalize — the session has let go of them, and so
        // it has of an FClosing one (a TLS connection draining its
        // close_notify already had UserData cleared).
        for I := 0 to FLiveCount - 1 do
          if FLive[I].Id = Node^.ConnId then
          begin
            if not (FLive[I].FDead or FLive[I].FClosing) then
              Conn := FLive[I];
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

// A parked GetQueuedCompletionStatus cannot notice a deadline pass.
// While any connection carries one, bound the park — this only ever
// SHORTENS the wait, so the Run(>= 0) contract still holds, and with
// TLS off FTimedCount is always zero and the wait is untouched.
function TWSIocpTransport.DeadlineBoundedWait(ATimeout: DWORD): DWORD;
begin
  Result := ATimeout;
  if FTimedCount <= 0 then Exit;
  if (Result = InfiniteWait) or (Result > DWORD(TlsDeadlinePollMs)) then
    Result := DWORD(TlsDeadlinePollMs);
end;

procedure TWSIocpTransport.Run(ATimeoutMs: Integer);
begin
  if FStopping then Exit;
  FRunning := True;
  if ATimeoutMs < 0 then
    repeat
      WaitAndDispatch(DeadlineBoundedWait(InfiniteWait));
      SweepPosts;
      if FTimedCount > 0 then SweepTlsDeadlines;
    until not FRunning
  else
  begin
    WaitAndDispatch(DeadlineBoundedWait(DWORD(ATimeoutMs)));
    SweepPosts;
    if FTimedCount > 0 then SweepTlsDeadlines;
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

  // HardClose, never SubmitClose: a TLS connection's SubmitClose may
  // defer for a close_notify drain, and Shutdown's contract is that no
  // completion can EVER fire again once it returns. A quiescing
  // listener aborts its TLS sessions (the abort rides the object's
  // destructor, the single teardown funnel). A connection suppressed by
  // encrypted-input backpressure carries no outstanding operation at
  // all, so HardClose reclaims it here and now instead of leaving the
  // drain below waiting for a completion that could never arrive.
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
