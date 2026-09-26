unit WS.Transport.Epoll;

// Linux transport: single-threaded epoll reactor implementing the
// WS.Transport completion contract. The shape every fast WebSocket
// server converges on — one event loop, nonblocking sockets,
// level-triggered readiness, EPOLLOUT armed only while a connection has
// backlog. Readiness adapts to the completion contract per ADR-0001:
// SubmitSend writes what the socket takes and arms EPOLLOUT for the
// remainder; EPOLLIN reads into ONE shared 256 KB buffer delivered via
// OnData, so by the next readiness event the buffer is free again. Zero
// steady-state allocation on the hot echo path. A readiness event reads
// until a short read or MaxFullReadsPerEvent full ones, never to EAGAIN
// (see ReadBudgetSpent): that last recv is a wasted syscall per message,
// and a peer that keeps its queue full would hold the loop forever.
// Readiness is level-triggered, so whatever is left is re-reported on the
// next epoll_wait. The cost: with server and peers sharing one core, the
// old loop stayed on one hot connection while the co-scheduled peer
// refilled it; this one walks the batch, which is slower for large
// payloads in that shape only (see docs/comparison.md).
//
// Server TLS (duetto#22) rides WS.Transport.TlsServer, which wraps
// lwpt's memory-BIO accept API. The reactor stays a byte mover: it owns
// the socket, the epoll interest set and the two reactor-owned guards
// (handshake deadline, inbound pre-handshake budget); the session unit
// owns every TLS state transition and all flow accounting. The two meet
// through one guarded fork per event — `if Conn.FTls <> nil` — so a
// plaintext listener runs the same code, with the same work per event,
// as it did before TLS existed.
//
// The TLS additions to the reactor proper are:
//   - a bounded epoll_wait timeout while any connection carries a
//     deadline (handshake pending, or a graceful close draining), so a
//     peer that goes silent still gets swept;
//   - EPOLLIN dropped from a connection's interest while lwpt reports
//     encrypted-input backpressure, restored on lwpt's own low-water
//     hysteresis;
//   - the socket read clamped to the configured encrypted-input
//     watermark, so that one number bounds a TLS connection's whole
//     inbound footprint rather than just lwpt's share of it;
//   - a deferred close: close_notify has to reach the socket before
//     FIN, which can outlive the SubmitClose that asked for it, and
//     which ends in a half-close plus an inbound drain rather than a
//     bare close() — see FinishDeferredClose.

{$I Shared.inc}

interface

{$ifdef LINUX}

uses
  BaseUnix,
  SysUtils,
  Unix,

  Linux,
  Sockets,
  TransportSecurity,
  WS.Transport,
  WS.Transport.PostQueue,
  WS.Transport.TlsServer;

type
  TWSEpollTransport = class;

  TWSEpollConn = class(TWSTransportConn)
  private
    FTransport: TWSEpollTransport;
    FFd: Integer;
    FWantWrite: Boolean;
    FDead: Boolean;
    // --- TLS only; all nil/False on a plaintext listener --------------
    FTls: TWSTlsServerSession;
    FInterest: Cardinal;       // last interest mask handed to epoll_ctl
    FPaused: Boolean;          // EPOLLIN dropped: encrypted input is full
    FInPump: Boolean;          // inside a TLS pump; teardown defers
    FFreeDeferred: Boolean;    // SubmitClose landed mid-pump
    FClosing: Boolean;         // graceful close draining; no callbacks
    // A SubmitSend went short: the session layer is holding output and
    // waiting for the OnSendReady the transport contract promises. It
    // is tracked separately from what the TLS engine owes the WIRE,
    // because the two clear at different moments — the engine can go
    // quiet (its retry drained, its ciphertext queue empty) while the
    // caller is still owed its re-offer, and dropping EPOLLOUT there
    // strands the connection with no event left to restart it.
    FSendReadyOwed: Boolean;
    FTimed: Boolean;           // counted in the reactor's deadline sweep
    FDeadline: QWord;          // close-drain deadline (monotonic)
    FFinSent: Boolean;         // half-closed; the drain is inbound-only
    procedure ApplyInterest;
    procedure SetTimed(AValue: Boolean);
    function RawSend(P: PByte; ALen: NativeInt): NativeInt;
    // TWSTlsServerSession callbacks.
    function TlsPlaintext(P: PByte; ALen: NativeInt): Boolean;
    function TlsCiphertext(P: PByte; ALen: NativeInt): NativeInt;
    function TlsSubmitSend(P: PByte; ALen: NativeInt): NativeInt;
    function TlsIngest(P: PByte; ALen: NativeInt): TWSTlsIngestResult;
    procedure ReconcileTlsInterest;
    procedure BeginDeferredClose;
    procedure StepDeferredClose;
    procedure FinishDeferredClose;
    procedure RunDeferredClose;
    procedure ForceClose;
  public
    destructor Destroy; override;
    function SubmitSend(P: PByte; ALen: NativeInt): NativeInt; override;
    procedure SubmitClose; override;
  end;

  // What spending the reserve descriptor on one accept achieved.
  TWSShedResult = (wsrShed, wsrDrained, wsrNoReserve);

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
    // TLS: one context for the listener's whole life, nil when off.
    FTlsContext: TTransportSecurityServerContext;
    FTlsPolicy: TWSTlsPolicy;
    FTimedCount: Integer;      // connections carrying a live deadline
    FTlsReadLen: Integer;      // per-round socket read bound on a TLS conn
    FNextSweepTick: QWord;     // deadline sweeps are amortized on the clock
    // Descriptor exhaustion. A level-triggered listener that cannot
    // accept stays readable, so an accept failure that is simply
    // returned from spins epoll_wait at full CPU without ever draining
    // the backlog. FReserveFd is one descriptor held open on /dev/null
    // for exactly that moment: close it, accept the waiting peer, close
    // the peer, take the reserve back — the backlog is shed instead of
    // spun on. When even that is not possible the listener leaves the
    // interest set until FAcceptBackoffUntil.
    FReserveFd: Integer;
    FAcceptBackoffUntil: QWord;

    procedure EpollMod(AConn: TWSEpollConn; AEvents: Cardinal);
    procedure Track(AConn: TWSEpollConn);
    procedure Untrack(AConn: TWSEpollConn);
    procedure AcceptPending;
    procedure ListenerArm(AArmed: Boolean);
    procedure OpenReserveFd;
    function ShedOneAccept: TWSShedResult;
    procedure HandleReadable(AConn: TWSEpollConn);
    procedure HandleReadableTls(AConn: TWSEpollConn);
    procedure HandleTlsEvent(AConn: TWSEpollConn; AEvents: Cardinal);
    procedure HandleTlsClosingEvent(AConn: TWSEpollConn; AEvents: Cardinal);
    procedure DrainClosingInput(AConn: TWSEpollConn);
    function DriveTlsWritable(AConn: TWSEpollConn): Boolean;
    procedure SweepTlsDeadlines(ANowTick: QWord);
    procedure MaybeSweepTlsDeadlines;
    procedure RemoteClosed(AConn: TWSEpollConn);
    procedure DeliverPosts(AChain: PWSPostNode; ADropped: Boolean);
  public
    // ABindAddress: '' = every interface; an IPv4 or IPv6 literal binds
    // that address (family chosen from the literal; see
    // WSParseBindAddress, which raises on anything else).
    constructor Create(APort: Word; const ATls: TWSTransportTls;
      const ABindAddress: string = '');
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
  // Granularity of the TLS deadline sweep. Only ever shortens an
  // epoll_wait that would otherwise park, and only while at least one
  // connection carries a deadline — a plaintext listener never sees it.
  TlsDeadlinePollMs = 100;
  // Full-length reads one readiness event may take before the reactor
  // moves on to the rest of the batch: 4 x 256 KB on a non-TLS
  // connection, 4 x the encrypted-input watermark under TLS. Level-
  // triggered EPOLLIN re-reports whatever is left on the next
  // epoll_wait, so this bounds how long one peer holds the loop without
  // dropping any of its bytes. 4 lets a bulk sender move ~1 MB per turn,
  // so epoll_wait round trips stay rare, and caps what any one peer can
  // take per turn at that same ~1 MB.
  MaxFullReadsPerEvent = 4;
  // Peers one listener event may shed while the descriptor table is
  // full. Shedding succeeds for as long as peers keep the backlog
  // populated, so it must hand the loop back: the level-triggered
  // listener is reported again on the next epoll_wait, alongside every
  // other connection's events.
  MaxShedPerEvent = 64;
  // How long the listener stays out of the interest set after accept
  // fails for lack of a resource the reserve descriptor cannot cover
  // (ENOBUFS/ENOMEM, or ENFILE with the reserve already spent). Short:
  // the backlog is still queueing peers meanwhile.
  AcceptBackoffMs = 100;
  ShutdownWrite = 1; // shutdown(): SHUT_WR

// The RTL's Linux unit predates eventfd on some targets; bind libc
// directly (explicit name — the formatter recases identifiers).
function C_eventfd(ACount: Cardinal; AFlags: Integer): Integer; cdecl;
  external name 'eventfd';
// Same treatment for shutdown(): the RTL's binding and its SHUT_*
// constants are not uniform across FPC's unix targets, and the IOCP
// transport binds its own for the same reason.
function C_shutdown(AFd: Integer; AHow: Integer): Integer; cdecl;
  external name 'shutdown';

// The per-event read bound shared by both read loops. A short read means
// nothing more was readable when it ran: the next recv would almost
// always report EAGAIN, and anything that arrives later (the peer running
// meanwhile, or packets queued while the socket was locked) is
// re-reported by level-triggered EPOLLIN. A full read may have more
// behind it, but only up to MaxFullReadsPerEvent, so one flooding peer
// cannot starve the rest of the batch.
function ReadBudgetSpent(AGot, AReadLen: Integer; var AFullReads: Integer): Boolean; inline;
begin
  if AGot < AReadLen then Exit(True);
  Inc(AFullReads);
  Result := AFullReads >= MaxFullReadsPerEvent;
end;

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

destructor TWSEpollConn.Destroy;
begin
  SetTimed(False);
  // Frees the lwpt session too (its destructor aborts); every teardown
  // path funnels here, so no branch can leak an OpenSSL session.
  FTls.Free;
  inherited;
end;

// The single place the interest mask is written. FPaused and the TLS
// fields are dead weight on a plaintext listener — the mask it computes
// there is exactly the EPOLLIN / EPOLLIN or EPOLLOUT pair the reactor
// always used — and the cached compare saves the redundant epoll_ctl
// the old code issued on every arm.
procedure TWSEpollConn.ApplyInterest;
var
  Ev: Cardinal;
begin
  Ev := 0;
  if not FPaused then Ev := Ev or EPOLLIN;
  if FWantWrite then Ev := Ev or EPOLLOUT;
  if Ev = FInterest then Exit;
  FInterest := Ev;
  FTransport.EpollMod(Self, Ev);
end;

procedure TWSEpollConn.SetTimed(AValue: Boolean);
begin
  if FTimed = AValue then Exit;
  FTimed := AValue;
  if AValue then
    Inc(FTransport.FTimedCount)
  else
    Dec(FTransport.FTimedCount);
end;

// Socket write, shared by the plaintext send path and the TLS
// ciphertext egress. Bytes taken, 0 on EAGAIN (EPOLLOUT armed), -1 when
// the connection is dead.
function TWSEpollConn.RawSend(P: PByte; ALen: NativeInt): NativeInt;
var
  W: NativeInt;
begin
  // A dead connection has no socket worth writing to (its fd may already
  // be closed); report the failure the caller expects, exactly as the
  // IOCP twin does. Reachable when a TLS pump flushes egress after an
  // earlier send in the same round already marked the connection dead.
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
          ApplyInterest;
        end;
        Exit;
      end;
      FDead := True;
      Exit(-1);
    end;
    Result := Result + W;
  end;
end;

function TWSEpollConn.SubmitSend(P: PByte; ALen: NativeInt): NativeInt;
begin
  if FDead then Exit(-1);
  if FTls <> nil then Exit(TlsSubmitSend(P, ALen));
  Result := RawSend(P, ALen);
  if (Result >= ALen) and FWantWrite then
  begin
    FWantWrite := False;
    ApplyInterest;
  end;
end;

procedure TWSEpollConn.SubmitClose;
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
  // An activated TLS session owes the peer close_notify before FIN;
  // that can outlive this call when the socket is backed up.
  if (FTls <> nil) and (not FDead) and (not FClosing) and
    FTls.HandshakeDone and (not FTls.Dead) then
  begin
    BeginDeferredClose;
    Exit;
  end;
  ForceClose;
end;

// Abortive teardown: no close_notify, no session callback. Every other
// teardown path ends here.
procedure TWSEpollConn.ForceClose;
begin
  FClosing := False;
  FTransport.Untrack(Self);
  Free;
end;

{ TWSEpollConn — TLS }

// Plaintext sink. False tells the pump to stop: the delivery tore this
// connection down and the session unit must not touch anything else.
// FDead is tested alongside FFreeDeferred so a send failure inside the
// delivery (RawSend marking the connection dead) stops the pump too —
// the same pair the IOCP twin returns.
function TWSEpollConn.TlsPlaintext(P: PByte; ALen: NativeInt): Boolean;
begin
  if Assigned(FTransport.OnData) then FTransport.OnData(Self, P, ALen);
  Result := (not FFreeDeferred) and (not FDead);
end;

// Ciphertext egress. The session unit consumes exactly what this
// returns, so a short write costs nothing but a later EPOLLOUT. The
// round's wire-progress marker lives in the session now (FlushEgress
// sets it as it hands bytes here), so the transport no longer records
// it separately.
function TWSEpollConn.TlsCiphertext(P: PByte; ALen: NativeInt): NativeInt;
begin
  Result := RawSend(P, ALen);
end;

// Interest reconciliation after any TLS pump: intake follows lwpt's
// input hysteresis, writability follows what the engine still owes the
// wire, and a completed handshake leaves the deadline sweep.
procedure TWSEpollConn.ReconcileTlsInterest;
begin
  if FTimed and (not FClosing) and FTls.HandshakeDone then SetTimed(False);
  FPaused := not FTls.MayResume;
  FWantWrite := FTls.NeedsWritable or FSendReadyOwed;
  ApplyInterest;
end;

function TWSEpollConn.TlsIngest(P: PByte;
  ALen: NativeInt): TWSTlsIngestResult;
begin
  FInPump := True;
  try
    Result := FTls.Ingest(P, ALen);
  finally
    FInPump := False;
  end;
  if FFreeDeferred then Exit; // teardown pending; do not touch epoll
  ReconcileTlsInterest;
end;

function TWSEpollConn.TlsSubmitSend(P: PByte; ALen: NativeInt): NativeInt;
begin
  Result := FTls.Encrypt(P, ALen);
  if Result < 0 then
  begin
    FDead := True;
    Exit(-1);
  end;
  // A short accept owes the caller an OnSendReady whatever caused it —
  // a full socket, or the encrypted-output capacity running out while
  // the socket stayed writable. Recording the debt before the
  // reconciliation is what keeps EPOLLOUT armed until it is paid: on a
  // writable socket the level-triggered reactor then delivers one on
  // the very next round.
  if Result < ALen then FSendReadyOwed := True;
  ReconcileTlsInterest;
end;

procedure TWSEpollConn.BeginDeferredClose;
begin
  FClosing := True;
  UserData := nil;
  // EPOLLIN deliberately STAYS armed, and inbound bytes are read and
  // discarded from here on (DrainClosingInput). Nothing the peer says
  // can matter any more, but leaving its bytes unread in the kernel
  // receive queue makes close() send RST instead of FIN — and a peer
  // whose stack then discards its own receive buffer loses the very
  // close_notify this drain exists to deliver. Draining is what keeps
  // the shutdown orderly; the IOCP transport learned the same lesson
  // against a Windows peer.
  FPaused := False;
  FDeadline := GetTickCount64 +
    QWord(FTransport.FTlsPolicy.HandshakeDeadlineMs);
  SetTimed(True);
  StepDeferredClose;
end;

procedure TWSEpollConn.StepDeferredClose;
begin
  if FTls.DrainClose or FTls.Dead then
  begin
    FinishDeferredClose;
    Exit;
  end;
  // Still bytes to push. EPOLLOUT is armed only while the drain actually
  // handed the wire something THIS round: NeedsWritable stays True on a
  // write retry lwpt parked on tssWantRead (it owes the wire in
  // principle but produced no ciphertext), and arming EPOLLOUT for that
  // on a permanently writable socket spins at 100% CPU until the
  // deadline. The same no-progress guard DriveTlsWritable uses, sourced
  // from the session: a drain that made wire progress keeps EPOLLOUT to
  // finish flushing; one that could not advance waits instead. EPOLLIN
  // stays armed throughout the close (BeginDeferredClose left it so), so
  // the close-drain deadline in the sweep is the backstop and a peer
  // that sends or hangs up re-enters here.
  FWantWrite := FTls.NeedsWritable and FTls.MadeWireProgress;
  ApplyInterest;
end;

// close_notify is out (or the session died trying). Half-close so the
// peer sees FIN rather than RST, then keep EPOLLIN armed and read-and-
// discard until the peer's own EOF reaps us. Two things go wrong with a
// bare close() here: Linux turns it into an RST whenever unread bytes
// are still queued, and a peer that receives RST may discard its own
// buffered-but-unread data — the alert included. shutdown(SHUT_WR)
// puts the FIN on the wire while the read side stays open for exactly
// as long as the drain needs. The close-drain deadline bounds a peer
// that reads the alert and then never closes.
procedure TWSEpollConn.FinishDeferredClose;
begin
  // A session that died on the way out has no orderly shutdown to
  // offer, and no reason to hold an fd waiting for a courtesy EOF.
  if FTls.Dead then
  begin
    ForceClose;
    Exit;
  end;
  if not FFinSent then
  begin
    FFinSent := True;
    C_shutdown(FFd, ShutdownWrite);
  end;
  FWantWrite := False;
  FPaused := False;
  ApplyInterest;
end;

// A pump deferred its own teardown; it has now unwound.
procedure TWSEpollConn.RunDeferredClose;
begin
  FFreeDeferred := False;
  SubmitClose;
end;

{ TWSEpollTransport }

constructor TWSEpollTransport.Create(APort: Word; const ATls: TWSTransportTls;
  const ABindAddress: string);
var
  Bind: TWSBindAddress;
  SA: TInetSockAddr;
  SA6: TInetSockAddr6;
  One, Family: Integer;
  Ev: TEPoll_Event;
  Len: TSockLen;
  Bound: Boolean;
begin
  inherited Create;
  // Before anything can raise: the destructor closes every fd >= 0, and
  // zero-initialized fields would close stdin.
  FListenFd := -1;
  FEpFd := -1;
  FWakeFd := -1;
  FReserveFd := -1;
  FPosts := TWSPostQueue.Create;
  // Validated before any fd exists: a bad literal fails the constructor
  // with nothing to clean up.
  Bind := WSParseBindAddress(ABindAddress);
  // Resolve and validate the whole TLS policy, and load the identity,
  // before the listener takes a port: a bad watermark or an unreadable
  // PKCS#12 must fail the constructor, not the first handshake.
  if ATls.Enabled then
  begin
    FTlsPolicy := WSTlsResolvePolicy(ATls);
    FTlsContext := WSTlsCreateServerContext(ATls, FTlsPolicy);
  end;
  SetLength(FRecv, 256 * 1024);
  // A TLS connection reads at most one encrypted-input watermark per
  // round: lwpt accepts no more than that per feed, and the remainder
  // would sit in the per-connection carry buffer — so a full 256 KB
  // read would let a flooding peer pin the configured bound PLUS the
  // difference. The clamp makes InputHighWater the whole per-connection
  // inbound bound, and makes it the same number on IOCP.
  FTlsReadLen := Length(FRecv);
  if (FTlsContext <> nil) and (FTlsPolicy.InputHighWater < FTlsReadLen) then
    FTlsReadLen := FTlsPolicy.InputHighWater;

  if Bind.Family = wbfInet6 then Family := AF_INET6 else Family := AF_INET;
  FListenFd := fpSocket(Family, SOCK_STREAM, 0);
  if FListenFd < 0 then raise Exception.Create('socket() failed');
  One := 1;
  fpSetSockOpt(FListenFd, SOL_SOCKET, SO_REUSEADDR, @One, SizeOf(One));

  // Accept never interprets the peer address (fpAccept with nil), so
  // the family only has to be right here and in the getsockname below.
  if Bind.Family = wbfInet6 then
  begin
    FillChar(SA6, SizeOf(SA6), 0);
    SA6.sin6_family := AF_INET6;
    SA6.sin6_port := htons(APort);
    Move(Bind.Bytes[0], SA6.sin6_addr, 16);
    Bound := fpBind(FListenFd, @SA6, SizeOf(SA6)) = 0;
  end
  else
  begin
    FillChar(SA, SizeOf(SA), 0);
    SA.sin_family := AF_INET;
    SA.sin_port := htons(APort);
    Move(Bind.Bytes[0], SA.sin_addr, 4); // all zero = INADDR_ANY
    Bound := fpBind(FListenFd, @SA, SizeOf(SA)) = 0;
  end;
  if not Bound then
  begin
    if Bind.Family = wbfAny then
      raise Exception.CreateFmt('bind to port %d failed', [APort]);
    raise Exception.CreateFmt('bind to %s port %d failed', [Bind.Text, APort]);
  end;
  if fpListen(FListenFd, 511) <> 0 then
    raise Exception.Create('listen() failed');

  // Port 0 = kernel-assigned; read back what we actually got.
  if Bind.Family = wbfInet6 then
  begin
    Len := SizeOf(SA6);
    fpGetSockName(FListenFd, @SA6, @Len);
    SetPort(ntohs(SA6.sin6_port));
  end
  else
  begin
    Len := SizeOf(SA);
    fpGetSockName(FListenFd, @SA, @Len);
    SetPort(ntohs(SA.sin_port));
  end;

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
  // Last: with one descriptor left, the reserve must not be what takes
  // it from the eventfd.
  OpenReserveFd;
end;

destructor TWSEpollTransport.Destroy;
begin
  Shutdown;
  FPosts.Free;
  // After Shutdown no connection holds a session against it any more.
  if FTlsContext <> nil then
    CloseTransportSecurityServerContext(FTlsContext);
  if FWakeFd >= 0 then FileClose(FWakeFd);
  if FEpFd >= 0 then FileClose(FEpFd);
  if FListenFd >= 0 then CloseSocket(FListenFd);
  if FReserveFd >= 0 then FileClose(FReserveFd);
  inherited;
end;

// Single-threaded (the Run thread is the only execution context and Run
// has returned by contract), so quiescing is closing every connection —
// but first the post queue is stopped: pending posts are delivered once
// as dropped (AConn = nil) so the session reclaims their envelopes, and
// any SubmitPost racing us is refused at Push and dropped by its own
// caller thread.
//
// Connections go through ForceClose rather than SubmitClose: a TLS
// connection's SubmitClose may defer for a close_notify drain, and
// Shutdown's contract is that no completion can EVER fire again once it
// returns. A quiescing listener aborts its TLS sessions.
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
      FConns[I].ForceClose;
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
        //
        // FClosing IS tested: a connection draining close_notify has
        // already been handed back to the transport (the session
        // dropped its reference and UserData is nil), so a post naming
        // it is a post for a connection that is gone.
        for I := 0 to High(FConns) do
          if (FConns[I] <> nil) and (FConns[I].Id = Node^.ConnId) and
            (not FConns[I].FClosing) then
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

procedure TWSEpollTransport.ListenerArm(AArmed: Boolean);
var
  Ev: TEPoll_Event;
begin
  if AArmed then
  begin
    Ev.events := EPOLLIN;
    Ev.data.u64 := QWord(Cardinal(FListenFd));
    // The same pressure that forced the backoff (ENOMEM, ENOSPC) can fail
    // the re-arm: keep a retry deadline, or the listener stays deaf.
    if epoll_ctl(FEpFd, EPOLL_CTL_ADD, FListenFd, @Ev) = 0 then
      FAcceptBackoffUntil := 0
    else
      FAcceptBackoffUntil := GetTickCount64 + QWord(AcceptBackoffMs);
  end
  else
  begin
    epoll_ctl(FEpFd, EPOLL_CTL_DEL, FListenFd, nil);
    FAcceptBackoffUntil := GetTickCount64 + QWord(AcceptBackoffMs);
  end;
end;

procedure TWSEpollTransport.OpenReserveFd;
begin
  if FReserveFd < 0 then
    FReserveFd := fpOpen('/dev/null', O_RDONLY or O_CLOEXEC);
end;

// The table is full: give the reserve back to the kernel, accept the
// peer at the head of the backlog, close it, take the reserve again.
// The peer sees an immediate close — the honest answer from a server
// with no descriptor to serve it — and the listener stops being
// readable for it. Linux checks the descriptor table before the
// backlog, so the outer accept reports EMFILE even once the backlog is
// empty: only the accept made with the reserve released can tell
// "another peer shed" from "nothing left to accept".
function TWSEpollTransport.ShedOneAccept: TWSShedResult;
var
  Fd: Integer;
begin
  if FReserveFd < 0 then Exit(wsrNoReserve);
  FileClose(FReserveFd);
  FReserveFd := -1;
  Fd := fpAccept(FListenFd, nil, nil);
  if Fd >= 0 then
  begin
    CloseSocket(Fd);
    Result := wsrShed;
  end
  else
    Result := wsrDrained;
  OpenReserveFd;
end;

procedure TWSEpollTransport.AcceptPending;
var
  Fd, Err, Shed: Integer;
  Conn: TWSEpollConn;
  Ev: TEPoll_Event;
begin
  Shed := 0;
  repeat
    Fd := fpAccept(FListenFd, nil, nil);
    if Fd < 0 then
    begin
      Err := fpGetErrno;
      case Err of
        ESysEINTR, ESysECONNABORTED:
          Continue; // interrupted, or the peer left the backlog: next
        ESysEMFILE, ESysENFILE:
          case ShedOneAccept of
            wsrShed:
              begin
                Inc(Shed);
                if Shed >= MaxShedPerEvent then Exit;
                Continue;
              end;
            wsrDrained: Exit;
          else
            ListenerArm(False);
            Exit;
          end;
        ESysENOBUFS, ESysENOMEM:
          begin
            ListenerArm(False);
            Exit;
          end;
      else
        Exit; // EAGAIN: drained
      end;
    end;
    SetNonBlocking(Fd);
    SetNoDelay(Fd);
    Conn := TWSEpollConn.Create;
    Conn.FTransport := Self;
    Conn.FFd := Fd;
    Conn.FInterest := EPOLLIN;
    // NativeUInt is 32-bit on a 32-bit target (CI builds i386-win32, and
    // any i386-linux build too), so the 2^32-th accept would trap under
    // {$Q+} and unwind the Run thread — killing the listener. Ids only
    // need to be unique among LIVE connections, so a wrap is harmless;
    // disable the overflow check for this one increment (mirrors IOCP).
    {$push}{$Q-}
    Inc(FNextId);
    {$pop}
    Conn.Id := FNextId;
    if FTlsContext <> nil then
    begin
      try
        Conn.FTls := TWSTlsServerSession.Create(FTlsContext, FTlsPolicy,
          Conn.TlsPlaintext, Conn.TlsCiphertext);
      except
        // A session lwpt refuses is this connection's problem, not the
        // listener's: drop it and keep accepting.
        Conn.Free;
        CloseSocket(Fd);
        Continue;
      end;
    end;
    Track(Conn);
    Ev.events := EPOLLIN;
    Ev.data.u64 := ConnEventData(Conn);
    epoll_ctl(FEpFd, EPOLL_CTL_ADD, Fd, @Ev);
    // The handshake clock starts at accept and is enforced by the
    // reactor, not by lwpt: a peer that connects and says nothing is
    // exactly the case no TLS engine can time out for us.
    if Conn.FTls <> nil then Conn.SetTimed(True);
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
  Fd, Got, FullReads: Integer;
  Gen: NativeUInt;
begin
  Fd := AConn.FFd;
  FullReads := 0;
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
    if Got < 0 then Exit; // EAGAIN; an error surfaces as EPOLLERR next round
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
    if ReadBudgetSpent(Got, Length(FRecv), FullReads) then Exit;
  until False;
end;

// The TLS twin of HandleReadable. Same shared read buffer, same
// generation invariant; the differences are that bytes go to the TLS
// session instead of straight to OnData, that the read is clamped to
// one encrypted-input watermark (FTlsReadLen), and that intake stops
// the moment lwpt reports encrypted-input backpressure.
procedure TWSEpollTransport.HandleReadableTls(AConn: TWSEpollConn);
var
  Fd, Got, FullReads: Integer;
  Gen: NativeUInt;
  Res: TWSTlsIngestResult;
begin
  Fd := AConn.FFd;
  Gen := AConn.Id;
  FullReads := 0;
  repeat
    if AConn.FPaused then Exit;
    Got := fpRecv(Fd, @FRecv[0], FTlsReadLen, 0);
    if Got = 0 then
    begin
      RemoteClosed(AConn);
      Exit;
    end;
    if Got < 0 then Exit; // EAGAIN; an error surfaces as EPOLLERR next round
    Res := AConn.TlsIngest(@FRecv[0], Got);
    if AConn.FFreeDeferred then
    begin
      // A plaintext delivery dropped this connection; the free waited
      // for the pump to unwind, which it just did.
      AConn.RunDeferredClose;
      Exit;
    end;
    if (Fd >= Length(FConns)) or (FConns[Fd] = nil) or
      (FConns[Fd].Id <> Gen) then Exit;
    if Res = wtiFailed then
    begin
      RemoteClosed(AConn);
      Exit;
    end;
    // Same bound as HandleReadable: backpressure alone does not stop a
    // peer whose ciphertext the session keeps up with.
    if ReadBudgetSpent(Got, FTlsReadLen, FullReads) then Exit;
  until False;
end;

// Writability on a TLS connection: push whatever the engine owes the
// wire, then let the session layer re-offer. False = do NOT touch AConn
// again this round — it is either gone (reaped here) or has moved into
// the close drain, which owns its own writability from here on. Both
// callers already treat False that way; it does not by itself mean the
// connection was freed.
function TWSEpollTransport.DriveTlsWritable(AConn: TWSEpollConn): Boolean;
var
  Fd: Integer;
  Gen: NativeUInt;
begin
  Result := False;
  Fd := AConn.FFd;
  Gen := AConn.Id;
  // Ingest with no new input is the pump: it flushes queued ciphertext,
  // resumes a write lwpt could not finish, drives a pending handshake
  // and decrypts whatever the input buffer still holds.
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
  if (FConns[Fd] = nil) or (FConns[Fd].Id <> Gen) then Exit;
  // Pay the debt before the callback, so a send inside it that goes
  // short can record a fresh one.
  AConn.FSendReadyOwed := False;
  // The callback runs outside any pump, so a drop inside it takes the
  // immediate path: either the connection is gone (the generation check
  // catches that before AConn is touched again) or it moved into the
  // close drain, which owns its own writability from here on.
  if Assigned(OnSendReady) then OnSendReady(AConn);
  if (FConns[Fd] = nil) or (FConns[Fd].Id <> Gen) then Exit;
  if AConn.FClosing then Exit;
  // The callback may have left nothing owed and nothing queued; without
  // this the connection would keep waking a permanently writable socket.
  AConn.ReconcileTlsInterest;
  // No-progress guard. A whole writable round in which the engine never
  // offered the socket a single byte cannot be improved by repeating
  // it: lwpt is parked on tssWantRead — a write retry waiting for
  // INPUT — and the reconciliation above would nonetheless keep
  // EPOLLOUT armed for the unpaid re-offer, which a level-triggered
  // reactor on a permanently writable socket turns into a 100% CPU
  // spin. Drop the write interest and let the next inbound event
  // re-arm it through the ordinary reconciliation; that event is
  // exactly what unblocks the state, and EPOLLIN is still armed for it
  // (the WriteParked case keeps intake un-paused precisely so it is).
  // The progress signal is the session's — it set it while flushing.
  if (not AConn.FTls.MadeWireProgress) and AConn.FWantWrite then
  begin
    AConn.FWantWrite := False;
    AConn.ApplyInterest;
  end;
  Result := True;
end;

// Everything a TLS connection's readiness can mean, in one place, so
// the plaintext dispatch in Run stays exactly what it was.
procedure TWSEpollTransport.HandleTlsEvent(AConn: TWSEpollConn;
  AEvents: Cardinal);
begin
  if AConn.FClosing then
  begin
    HandleTlsClosingEvent(AConn, AEvents);
    Exit;
  end;
  if (AEvents and (EPOLLERR or EPOLLHUP)) <> 0 then
  begin
    RemoteClosed(AConn);
    Exit;
  end;
  if (AEvents and EPOLLOUT) <> 0 then
    if not DriveTlsWritable(AConn) then Exit;
  if (AEvents and EPOLLIN) <> 0 then
    HandleReadableTls(AConn);
end;

// Readiness on a connection draining its close_notify. No session
// callbacks are left to make, so this is pure byte movement in two
// directions: EPOLLOUT pushes whatever the alert still owes the wire,
// EPOLLIN reads and DISCARDS whatever the peer keeps sending. The
// inbound half is not politeness — see FinishDeferredClose: unread
// bytes in the receive queue turn the eventual close() into an RST,
// which can cost the peer the alert it has not read yet.
procedure TWSEpollTransport.HandleTlsClosingEvent(AConn: TWSEpollConn;
  AEvents: Cardinal);
var
  Fd: Integer;
  Gen: NativeUInt;
begin
  // A socket error means the peer will never read the alert; stop
  // trying. EPOLLHUP is NOT in this test any more: a half-closed
  // connection whose peer has also closed reports it, and that case
  // wants the read below, which reaps on the EOF it finds.
  if (AEvents and EPOLLERR) <> 0 then
  begin
    AConn.ForceClose;
    Exit;
  end;
  Fd := AConn.FFd;
  Gen := AConn.Id;
  if (AEvents and EPOLLOUT) <> 0 then
  begin
    AConn.StepDeferredClose; // may finish the drain and free AConn
    if (FConns[Fd] = nil) or (FConns[Fd].Id <> Gen) then Exit;
  end;
  if (AEvents and (EPOLLIN or EPOLLHUP)) <> 0 then
    DrainClosingInput(AConn);
end;

// Read and drop what the peer sends while we are closing. ONE
// FTlsReadLen-sized read per readiness round, not a drain-to-EAGAIN
// loop: a peer streaming during our close_notify drain would otherwise
// hold the single-threaded reactor hostage across an unbounded read
// loop, starving every other connection — the IOCP twin is naturally
// bounded at one WSARecv per completion and this must match it. Level-
// triggered EPOLLIN brings us straight back next round if the socket
// still has bytes; the close-drain deadline in the sweep bounds a peer
// that neither sends nor closes. The read is FTlsReadLen, the documented
// per-connection inbound bound, not the whole 256 KB shared buffer.
procedure TWSEpollTransport.DrainClosingInput(AConn: TWSEpollConn);
var
  Got: Integer;
begin
  Got := fpRecv(AConn.FFd, @FRecv[0], FTlsReadLen, 0);
  if Got > 0 then Exit; // more may wait; the next EPOLLIN round takes it
  if (Got < 0) and (fpgeterrno = ESysEAGAIN) then Exit;
  // EOF, or a read error on a socket we have nothing left to say to.
  AConn.ForceClose;
end;

// Reactor-owned deadlines. Two kinds:
//   - handshake pending: a peer that connected and then went quiet (or
//     trickles just enough to look alive) is aborted;
//   - graceful close draining: a peer that stopped reading must not
//     pin the fd forever waiting for its close_notify to fit.
//
// The skip precondition is deliberately the same one the IOCP sweep
// uses — "not carrying a clock, or already reaped" — even though the
// two transports spell "already reaped" differently: IOCP has a
// pending-finalize state (FDead with pins outstanding) and tests it,
// while epoll untracks synchronously, so an entry still in this table
// is by construction not reaped and needs no test. The reap condition
// matches too: a session that is dead can never activate, so it leaves
// on the same pass a timed-out one does.
procedure TWSEpollTransport.SweepTlsDeadlines(ANowTick: QWord);
var
  I: Integer;
  Conn: TWSEpollConn;
begin
  for I := 0 to High(FConns) do
  begin
    Conn := FConns[I];
    if (Conn = nil) or (not Conn.FTimed) then Continue;
    if Conn.FClosing then
    begin
      if ANowTick >= Conn.FDeadline then Conn.ForceClose;
    end
    else if Conn.FTls.Dead or Conn.FTls.DeadlineExpired then
      RemoteClosed(Conn);
  end;
end;

// The sweep is O(connection table), so running it after every
// epoll_wait batch is O(table) per batch — and under handshake churn
// FTimedCount is permanently positive, so "only while a deadline
// exists" is no bound at all. Gate it on the clock instead: the
// deadline resolution is TlsDeadlinePollMs either way (that is already
// the epoll_wait bound a live deadline imposes), so amortizing to one
// scan per poll interval costs nothing and removes the per-batch cost.
procedure TWSEpollTransport.MaybeSweepTlsDeadlines;
var
  NowTick: QWord;
begin
  if FTimedCount <= 0 then Exit;
  NowTick := GetTickCount64;
  if NowTick < FNextSweepTick then Exit;
  FNextSweepTick := NowTick + QWord(TlsDeadlinePollMs);
  SweepTlsDeadlines(NowTick);
end;

procedure TWSEpollTransport.Run(ATimeoutMs: Integer);
var
  Evs: array[0..255] of TEPoll_Event;
  N, I, Fd, Wait: Integer;
  Conn: TWSEpollConn;
  Gen: NativeUInt;
  Wake: UInt64;
begin
  FRunning := True;
  repeat
    // A parked Run(-1) cannot notice a deadline pass. While any
    // connection carries one, bound the park — this only ever SHORTENS
    // the wait, so the Run(>= 0) contract still holds, and with TLS off
    // FTimedCount is always zero and the wait is untouched.
    Wait := ATimeoutMs;
    if FTimedCount > 0 then
      if (Wait < 0) or (Wait > TlsDeadlinePollMs) then Wait := TlsDeadlinePollMs;
    // A backed-off listener needs the same courtesy: wake in time to
    // put it back.
    if FAcceptBackoffUntil <> 0 then
      if (Wait < 0) or (Wait > AcceptBackoffMs) then Wait := AcceptBackoffMs;
    N := epoll_wait(FEpFd, @Evs[0], Length(Evs), Wait);
    if (FAcceptBackoffUntil <> 0) and (GetTickCount64 >= FAcceptBackoffUntil) then
      ListenerArm(True);
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
      // The one TLS fork in the dispatch loop: a plaintext listener
      // pays a single never-taken branch, and everything below stays
      // byte-for-byte the reactor it always was.
      if Conn.FTls <> nil then
      begin
        HandleTlsEvent(Conn, Evs[I].events);
        Continue;
      end;
      if (Evs[I].events and (EPOLLERR or EPOLLHUP)) <> 0 then
      begin
        RemoteClosed(Conn);
        Continue;
      end;
      if (Evs[I].events and EPOLLOUT) <> 0 then
      begin
        Conn.FWantWrite := False;
        Conn.ApplyInterest;
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
    MaybeSweepTlsDeadlines;
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
