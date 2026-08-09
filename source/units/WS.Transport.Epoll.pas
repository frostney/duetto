unit WS.Transport.Epoll;

// Linux transport: single-threaded epoll reactor implementing the
// WS.Transport completion contract. The shape every fast WebSocket
// server converges on — one event loop, nonblocking sockets,
// level-triggered readiness, EPOLLOUT armed only while a connection has
// backlog. Readiness adapts to the completion contract per ADR-0001:
// SubmitSend writes what the socket takes and arms EPOLLOUT for the
// remainder; EPOLLIN drains into ONE shared 256 KB buffer delivered via
// OnData, so by the next readiness event the buffer is free again. Zero
// steady-state allocation on the hot echo path.

{$I Shared.inc}

interface

{$ifdef LINUX}

uses
  BaseUnix,
  SysUtils,
  Unix,

  Linux,
  Sockets,
  WS.Transport,
  WS.Transport.PostQueue;

type
  TWSEpollTransport = class;

  TWSEpollConn = class(TWSTransportConn)
  private
    FTransport: TWSEpollTransport;
    FFd: Integer;
    FWantWrite: Boolean;
    FDead: Boolean;
  public
    function SubmitSend(P: PByte; ALen: NativeInt): NativeInt; override;
    procedure SubmitClose; override;
  end;

  TWSEpollTransport = class(TWSTransport)
  private
    FListenFd, FEpFd: Integer;
    FWakeFd: Integer;          // eventfd; Stop()/SubmitPost write, Run() wakes
    FConns: array of TWSEpollConn;   // fd-indexed
    FRecv: TBytes;                   // shared read buffer
    FPosts: TWSPostQueue;            // cross-thread SubmitPost hand-off
    FRunning: Boolean;
    FShutdownDone: Boolean;
    FNextId: NativeUInt;

    procedure EpollMod(AConn: TWSEpollConn; AEvents: Cardinal);
    procedure Track(AConn: TWSEpollConn);
    procedure Untrack(AConn: TWSEpollConn);
    procedure AcceptPending;
    procedure HandleReadable(AConn: TWSEpollConn);
    procedure RemoteClosed(AConn: TWSEpollConn);
    procedure DeliverPosts(AChain: PWSPostNode; ADropped: Boolean);
  public
    constructor Create(APort: Word; const ATls: TWSTransportTls);
    destructor Destroy; override;
    procedure Run(ATimeoutMs: Integer = -1); override;
    procedure Stop; override;
    procedure Shutdown; override;
    procedure SubmitPost(AConnId: NativeUInt; AData: Pointer); override;
  end;

{$endif}

implementation

{$ifdef LINUX}

const
  ConnTableGrowth = 64;
  EFD_NONBLOCK = $800;

// The RTL's Linux unit predates eventfd on some targets; bind libc
// directly (explicit name — the formatter recases identifiers).
function C_eventfd(ACount: Cardinal; AFlags: Integer): Integer; cdecl;
  external name 'eventfd';

procedure SetNonBlocking(AFd: Integer);
var
  Fl: Integer;
begin
  Fl := FpFcntl(AFd, F_GETFL, 0);
  FpFcntl(AFd, F_SETFL, Fl or O_NONBLOCK);
end;

procedure SetNoDelay(AFd: Integer);
var
  One: Integer;
begin
  One := 1;
  fpSetSockOpt(AFd, IPPROTO_TCP, TCP_NODELAY, @One, SizeOf(One));
end;

{ TWSEpollConn }

function TWSEpollConn.SubmitSend(P: PByte; ALen: NativeInt): NativeInt;
var
  W: NativeInt;
begin
  if FDead then Exit(-1);
  Result := 0;
  while Result < ALen do
  begin
    W := fpSend(FFd, P + Result, ALen - Result, MSG_NOSIGNAL);
    if W < 0 then
    begin
      if fpgeterrno = ESysEAGAIN then
      begin
        if not FWantWrite then
        begin
          FWantWrite := True;
          FTransport.EpollMod(Self, EPOLLIN or EPOLLOUT);
        end;
        Exit;
      end;
      FDead := True;
      Exit(-1);
    end;
    Result := Result + W;
  end;
  if FWantWrite then
  begin
    FWantWrite := False;
    FTransport.EpollMod(Self, EPOLLIN);
  end;
end;

procedure TWSEpollConn.SubmitClose;
begin
  FTransport.Untrack(Self);
  Free;
end;

{ TWSEpollTransport }

constructor TWSEpollTransport.Create(APort: Word; const ATls: TWSTransportTls);
var
  SA: TInetSockAddr;
  One: Integer;
  Ev: TEPoll_Event;
  Len: TSockLen;
begin
  inherited Create;
  // Before anything can raise: the destructor closes every fd >= 0, and
  // zero-initialized fields would close stdin.
  FListenFd := -1;
  FEpFd := -1;
  FWakeFd := -1;
  FPosts := TWSPostQueue.Create;
  if ATls.Enabled then
    raise Exception.Create(
      'epoll transport has no TLS yet; tracked as duetto#22 (upstream ' +
      'contracts shipped in lwpt 0.5.0; duetto wiring pending). Run ' +
      'behind a TLS-terminating proxy');
  SetLength(FRecv, 256 * 1024);

  FListenFd := fpSocket(AF_INET, SOCK_STREAM, 0);
  if FListenFd < 0 then raise Exception.Create('socket() failed');
  One := 1;
  fpSetSockOpt(FListenFd, SOL_SOCKET, SO_REUSEADDR, @One, SizeOf(One));

  FillChar(SA, SizeOf(SA), 0);
  SA.sin_family := AF_INET;
  SA.sin_port := htons(APort);
  SA.sin_addr.s_addr := 0; // INADDR_ANY
  if fpBind(FListenFd, @SA, SizeOf(SA)) <> 0 then
    raise Exception.CreateFmt('bind to port %d failed', [APort]);
  if fpListen(FListenFd, 511) <> 0 then
    raise Exception.Create('listen() failed');

  // Port 0 = kernel-assigned; read back what we actually got.
  Len := SizeOf(SA);
  fpGetSockName(FListenFd, @SA, @Len);
  SetPort(ntohs(SA.sin_port));

  SetNonBlocking(FListenFd);

  FEpFd := epoll_create(1024);
  if FEpFd < 0 then raise Exception.Create('epoll_create failed');
  Ev.events := EPOLLIN;
  // Special fds ride the same u64 as connection events with a zero
  // generation tag; Ev is a stack local, so data.fd alone would leave
  // garbage in the tag half.
  Ev.data.u64 := QWord(Cardinal(FListenFd));
  epoll_ctl(FEpFd, EPOLL_CTL_ADD, FListenFd, @Ev);

  // Stop() must unblock a Run(-1) parked in epoll_wait from another
  // thread; an eventfd in the interest set is the wakeup channel.
  FWakeFd := C_eventfd(0, EFD_NONBLOCK);
  if FWakeFd >= 0 then
  begin
    Ev.events := EPOLLIN;
    Ev.data.u64 := QWord(Cardinal(FWakeFd));
    epoll_ctl(FEpFd, EPOLL_CTL_ADD, FWakeFd, @Ev);
  end;
end;

destructor TWSEpollTransport.Destroy;
begin
  Shutdown;
  FPosts.Free;
  if FWakeFd >= 0 then FileClose(FWakeFd);
  if FEpFd >= 0 then FileClose(FEpFd);
  if FListenFd >= 0 then CloseSocket(FListenFd);
  inherited;
end;

// Single-threaded (the Run thread is the only execution context and Run
// has returned by contract), so quiescing is closing every connection —
// but first the post queue is stopped: pending posts are delivered once
// as dropped (AConn = nil) so the session reclaims their envelopes, and
// any SubmitPost racing us is refused at Push and dropped by its own
// caller thread.
//
// Idempotent, and explicitly so: the body already was (a stopped queue
// re-Stops to nil, an emptied table re-scans to nothing), but Destroy
// calls this after the session may have called it, and the guard makes
// that contract match the IOCP and Network.framework transports rather
// than resting on the body staying accidentally re-entrant.
procedure TWSEpollTransport.Shutdown;
var
  I: Integer;
begin
  if FShutdownDone then Exit;
  FShutdownDone := True;
  DeliverPosts(FPosts.Stop, True);
  for I := 0 to High(FConns) do
    if FConns[I] <> nil then
      FConns[I].SubmitClose;
end;

// Run-thread only (or Shutdown, with Run returned): serialized with
// every other completion by construction. ADropped skips the conn
// lookup so shutdown reclaims envelopes without touching connections.
procedure TWSEpollTransport.DeliverPosts(AChain: PWSPostNode;
  ADropped: Boolean);
var
  Node, Next: PWSPostNode;
  Conn: TWSEpollConn;
  I: Integer;
begin
  Node := AChain;
  try
    while Node <> nil do
    begin
      Conn := nil;
      if not ADropped then
        // The table is fd-indexed; posts are cold path, a scan is fine.
        // Re-scanned per node: the previous OnPost may have torn any
        // connection down.
        //
        // Deliberately NO FDead test here, unlike the IOCP and
        // Network.framework scans: epoll's FDead means only "a send
        // failed and the session has not been told yet" — the
        // connection is still tracked and still the session's to use.
        // Untrack is synchronous (SubmitClose and RemoteClosed remove
        // the table entry before returning), so this transport has no
        // pending-finalize state a post could land on. Do not "fix"
        // this to match the other two.
        for I := 0 to High(FConns) do
          if (FConns[I] <> nil) and (FConns[I].Id = Node^.ConnId) then
          begin
            Conn := FConns[I];
            Break;
          end;
      Next := Node^.Next;
      try
        if Assigned(OnPost) then OnPost(Conn, Node^.Data);
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

procedure TWSEpollTransport.SubmitPost(AConnId: NativeUInt; AData: Pointer);
var
  One: UInt64;
begin
  if not FPosts.Push(AConnId, AData) then
  begin
    // Stopped: dropped on the calling thread.
    if Assigned(OnPost) then OnPost(nil, AData);
    Exit;
  end;
  // Wake the reactor through the same eventfd Stop uses; Run drains the
  // queue on the next round. The wake is an optimization, not the
  // delivery mechanism: Run sweeps FPosts once per epoll_wait batch, so
  // a post is delivered on the next round the reactor makes either way.
  // That covers both ways the wake can go missing:
  //   - no eventfd at all (creation failed) — delivery then waits for
  //     the next epoll_wait return, readiness or timeout, exactly as
  //     Stop does;
  //   - the write fails with EAGAIN — the eventfd counter is saturated
  //     at UINT64_MAX - 1, which means a wake is already posted and
  //     unread; the round it triggers picks this node up. Self-healing,
  //     so the return value is deliberately not checked.
  if FWakeFd >= 0 then
  begin
    One := 1;
    fpWrite(FWakeFd, One, SizeOf(One));
  end;
end;

// Connection events carry a generation tag alongside the fd: the low
// 32 bits of epoll_data.u64 are the fd, the high 32 the connection
// Id's low word. The kernel reuses a closed fd for the next accept, so
// within one epoll_wait batch a stale event for a dropped connection
// can name the fd of a connection accepted later in the same round —
// the tag lets Run tell the two occupants apart and drop the stale
// event instead of tearing down the newcomer.
function ConnEventData(AConn: TWSEpollConn): QWord;
begin
  Result := (QWord(Cardinal(AConn.Id)) shl 32) or QWord(Cardinal(AConn.FFd));
end;

procedure TWSEpollTransport.EpollMod(AConn: TWSEpollConn; AEvents: Cardinal);
var
  Ev: TEPoll_Event;
begin
  Ev.events := AEvents;
  Ev.data.u64 := ConnEventData(AConn);
  epoll_ctl(FEpFd, EPOLL_CTL_MOD, AConn.FFd, @Ev);
end;

procedure TWSEpollTransport.Track(AConn: TWSEpollConn);
begin
  if AConn.FFd >= Length(FConns) then
    SetLength(FConns, AConn.FFd + ConnTableGrowth);
  FConns[AConn.FFd] := AConn;
end;

procedure TWSEpollTransport.Untrack(AConn: TWSEpollConn);
begin
  epoll_ctl(FEpFd, EPOLL_CTL_DEL, AConn.FFd, nil);
  CloseSocket(AConn.FFd);
  FConns[AConn.FFd] := nil;
end;

procedure TWSEpollTransport.AcceptPending;
var
  Fd: Integer;
  Conn: TWSEpollConn;
  Ev: TEPoll_Event;
begin
  repeat
    Fd := fpAccept(FListenFd, nil, nil);
    if Fd < 0 then Exit; // EAGAIN: drained
    SetNonBlocking(Fd);
    SetNoDelay(Fd);
    Conn := TWSEpollConn.Create;
    Conn.FTransport := Self;
    Conn.FFd := Fd;
    Inc(FNextId);
    Conn.Id := FNextId;
    Track(Conn);
    Ev.events := EPOLLIN;
    Ev.data.u64 := ConnEventData(Conn);
    epoll_ctl(FEpFd, EPOLL_CTL_ADD, Fd, @Ev);
    if Assigned(OnAccept) then OnAccept(Conn);
  until False;
end;

// Remote close or transport error: session is told once via OnClosed,
// then the transport reclaims the connection.
procedure TWSEpollTransport.RemoteClosed(AConn: TWSEpollConn);
begin
  Untrack(AConn);
  if Assigned(OnClosed) then OnClosed(AConn);
  AConn.Free;
end;

procedure TWSEpollTransport.HandleReadable(AConn: TWSEpollConn);
var
  Fd, Got: Integer;
  Gen: NativeUInt;
begin
  Fd := AConn.FFd;
  // Identity for the mid-dispatch re-check below is the generation, not
  // the pointer: AConn may be freed memory by the time we look, so the
  // Id is captured here, while it is still ours to read.
  Gen := AConn.Id;
  repeat
    Got := fpRecv(Fd, @FRecv[0], Length(FRecv), 0);
    if Got = 0 then
    begin
      RemoteClosed(AConn);
      Exit;
    end;
    if Got < 0 then Exit; // EAGAIN
    if Assigned(OnData) then OnData(AConn, @FRecv[0], Got);
    // Invariant: the fd is still ours only while the table occupant is
    // the same CONNECTION GENERATION we entered with. The session may
    // have torn this connection down inside OnData, and — since an
    // accept can run inside a handler (a posted proc reaching back into
    // the reactor) — the kernel may already have handed the same fd to
    // a newer connection. A pointer compare would miss that; a
    // generation compare cannot.
    if (Fd >= Length(FConns)) or (FConns[Fd] = nil) or
      (FConns[Fd].Id <> Gen) then Exit;
  until False;
end;

procedure TWSEpollTransport.Run(ATimeoutMs: Integer);
var
  Evs: array[0..255] of TEPoll_Event;
  N, I, Fd: Integer;
  Conn: TWSEpollConn;
  Gen: NativeUInt;
  Wake: UInt64;
begin
  FRunning := True;
  repeat
    N := epoll_wait(FEpFd, @Evs[0], Length(Evs), ATimeoutMs);
    for I := 0 to N - 1 do
    begin
      Fd := Integer(Cardinal(Evs[I].data.u64)); // low half: the fd
      if Fd = FWakeFd then
      begin
        fpRead(FWakeFd, Wake, SizeOf(Wake)); // drain the counter
        // The eventfd serves two producers: Stop (the loop condition
        // sees FRunning = False) and SubmitPost (deliver now, on this
        // thread, serialized with every other completion).
        DeliverPosts(FPosts.Drain, False);
        Continue;
      end;
      if Fd = FListenFd then
      begin
        AcceptPending;
        Continue;
      end;
      if (Fd >= Length(FConns)) or (FConns[Fd] = nil) then Continue;
      Conn := FConns[Fd];
      // Generation check: a drop earlier in this batch (OnData, a
      // posted proc) closed some fd, and a later accept in the same
      // batch may have reused it — a stale event for the previous
      // occupant must not touch the newcomer.
      if Cardinal(Conn.Id) <> Cardinal(Evs[I].data.u64 shr 32) then
        Continue;
      if (Evs[I].events and (EPOLLERR or EPOLLHUP)) <> 0 then
      begin
        RemoteClosed(Conn);
        Continue;
      end;
      if (Evs[I].events and EPOLLOUT) <> 0 then
      begin
        Conn.FWantWrite := False;
        EpollMod(Conn, EPOLLIN);
        // Same invariant as HandleReadable: the fd stays ours only
        // while the table occupant is the generation we dispatched.
        // Capture the Id before the callback — Conn may be freed by it.
        Gen := Conn.Id;
        if Assigned(OnSendReady) then OnSendReady(Conn);
        if (FConns[Fd] = nil) or (FConns[Fd].Id <> Gen) then Continue;
      end;
      if (Evs[I].events and EPOLLIN) <> 0 then
        HandleReadable(Conn);
    end;
    // Wake-independent backstop (once per batch, never per event): a
    // post whose eventfd wake was lost, or that landed after this
    // round's drain, is picked up on the next readiness event. Not
    // absolute: an idle Run(-1) reactor with a lost wake produces no
    // batch, so that post waits for traffic or Shutdown — acceptable
    // because eventfd loss is only the (self-healing) saturated-counter
    // case. The dirty HasPending read costs one branch per epoll_wait.
    if FPosts.HasPending then DeliverPosts(FPosts.Drain, False);
  until (not FRunning) or (ATimeoutMs >= 0);
end;

procedure TWSEpollTransport.Stop;
var
  One: UInt64;
begin
  FRunning := False;
  if FWakeFd >= 0 then
  begin
    One := 1;
    fpWrite(FWakeFd, One, SizeOf(One));
  end;
end;

{$endif}

end.
