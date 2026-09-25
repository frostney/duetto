unit WS.Server;

// Platform-neutral WebSocket server session layer. Per connection: a
// TWSProtocol does every byte of RFC 6455; this unit only moves bytes
// between the platform transport (WS.Transport, selected per platform
// below) and that machine. Handshakes are accumulated until the blank
// line, parsed by WS.Handshake, answered, and the connection flips from
// "handshaking" to "open". A well-formed non-upgrade request may
// instead be answered by the host via OnPlainRequest (single-shot,
// then close); with the hook unset it is refused exactly as before.
// Between parse and answer of a valid upgrade the host may veto it via
// OnUpgradeRequest (403, then close); with that hook unset every
// well-formed upgrade is accepted exactly as before.
//
// Concurrency (ADR-0003): callbacks fire on the transport's execution
// context — the Run thread on Linux (epoll) and Windows (IOCP),
// per-connection serial dispatch queues on macOS (Network.framework).
// Per-connection order is guaranteed everywhere; handlers for DIFFERENT
// connections may run concurrently on macOS, so cross-connection state
// in user handlers needs the user's own synchronization. The hot path
// here is confined to one connection and stays lock-free; the only lock
// guards the connection registry on accept/close (cold path).
// TWSConnection.Post is the one cross-thread hand-off: it schedules a
// proc onto the connection's callback context via the transport seam,
// so server-driven pushes need no locks of their own.

{$I Shared.inc}

interface

{$if defined(LINUX) or defined(DARWIN) or defined(WINDOWS)}

uses
  Classes,
  syncobjs,
  SysUtils,

  WS.Handshake,
  WS.Protocol,
  WS.Transport;

type
  TWSServer = class;
  TWSConnection = class;

  TWSConnState = (wcsHandshake, wcsOpen, wcsClosing);

  // FPC 3.2.2 has no anonymous methods ("reference to"), so a plain
  // method pointer is the closure type: two raw pointers, nothing to
  // heap-manage, and it carries the object state a push source needs.
  TWSConnProc = procedure(AConn: TWSConnection) of object;

  TWSConnection = class
  private
    FServer: TWSServer;
    FTConn: TWSTransportConn;
    // The transport's id, cached at accept: Id and Post must not reach
    // through FTConn once the transport may have freed it (Destroy).
    FId: NativeUInt;
    FState: TWSConnState;
    FProto: TWSProtocol;
    FHsBuf: RawByteString;     // handshake accumulator
    // Drop this connection as soon as its out queue drains. Set both by
    // the failure path (protocol error: get the close frame out, then
    // die) and by the successful single-shot plain-HTTP response (write
    // the body, then close — there is no keep-alive).
    FDropPending: Boolean;
    FInDelivery: Boolean;      // inside Ingest/OnOpen delivery — drops defer
    FDropping: Boolean;        // teardown running; re-entrant drops no-op
    FDropDeferred: Boolean;    // dropped mid-delivery; freed on unwind
    // Clock state, all in GetTickCount64 milliseconds, written only on
    // this connection's execution context. FDeadline is when the peer
    // must have done what the current state is waiting for (finished
    // the handshake, answered a close, read a draining response, sent
    // any byte at all when idle timing is on); FPingDue is when the
    // keepalive ping goes out; 0 = not armed. FSweepAt is the earlier
    // of the two and the one field the sweeper thread reads — racily,
    // by design: a torn or stale read only costs a spare post, because
    // the posted check re-judges against the authoritative values on
    // this context. FSweepPosted keeps the sweeper from re-posting an
    // already queued check; it is set right before each post and
    // cleared by that post's proc before it judges anything.
    FDeadline: QWord;
    FPingDue: QWord;
    FSweepAt: QWord;
    FSweepPosted: Boolean;
    // Own slot in FServer.FRegistry, or -1 when unregistered (set at
    // construction, before the object is reachable). Once registered,
    // written and read only under FServer.FLock; makes the Post
    // rendezvous O(1) instead of a scan of every live connection.
    FRegistryIndex: Integer;
    procedure Reschedule;
    procedure ArmDeadline(AMs: Integer);
    procedure NoteActivity;
    procedure CheckClock(AConn: TWSConnection);
    procedure ProtoMessage(AText: Boolean; P: PByte; ALen: NativeInt);
    function GetId: NativeUInt;
  public
    UserData: Pointer;
    constructor Create;
    destructor Destroy; override;
    // Callable from this connection's callback context (ADR-0003).
    // False = the transport reported the connection dead during the
    // flush: the connection was dropped and the reference must not be
    // touched again. OnClientClose fires as part of that drop —
    // nested inside this call when the drop is immediate, or after the
    // current OnMessage/OnOpen delivery unwinds when it is deferred
    // (the free is deferred there so pipelined frames cannot be parsed
    // in freed memory). True = the connection is still alive,
    // including the no-op cases (not yet open, already closing). This
    // matches the pre-seam reactor's drop semantics; ignoring the
    // result is legal Pascal and keeps old callers valid.
    //
    // True is a liveness signal, NOT a delivery or queueing one: it is
    // also what you get when the call did nothing at all (state is not
    // wcsOpen — still handshaking, or already closing) and when the
    // protocol layer discarded the message for its own reasons. The
    // only thing this result reports is False = dropped; if you need to
    // know that bytes were actually queued, track it at the protocol
    // layer, not here. Inside your own OnClientClose handler the
    // connection is already being dropped, so these return False
    // without queueing anything.
    function SendText(P: PByte; ALen: NativeInt): Boolean;
    function SendBinary(P: PByte; ALen: NativeInt): Boolean;
    // Same contract as SendText/SendBinary: False = the transport
    // declared the connection dead while the close frame flushed and
    // the connection was dropped (freed before Close returns, or right
    // after the current OnMessage/OnOpen delivery unwinds) — do not
    // touch the reference again. True = still alive, including the
    // no-op case where the connection was not open to begin with.
    function Close(ACode: Word = 1000; const AReason: string = ''): Boolean;
    // Runs AProc on this connection's callback context with the same
    // guarantees as OnMessage (ADR-0003): serialized with the
    // connection's other callbacks, in post order per calling thread.
    // Callable from ANY thread — the one cross-thread hand-off the API
    // has; SendText/SendBinary/Close inside AProc behave exactly as
    // they do inside OnMessage.
    //
    // Lifetime contract: hold connection references only from OnOpen
    // until your OnClientClose handler returns — inside that window
    // Self is guaranteed allocated, and Post on a connection that is
    // concurrently dropping is safe: the post is silently discarded.
    // Posts still in flight when the connection drops or the server
    // shuts down are discarded too (AProc never runs; the internal
    // envelope is freed). Posting after your OnClientClose returned,
    // or racing TWSServer.Destroy, is undefined behaviour (on the
    // Network.framework backend such a race can still deliver AProc
    // mid-teardown rather than discarding it).
    //
    // A nil AProc is a no-op: nothing is scheduled and nothing runs.
    procedure Post(AProc: TWSConnProc);
    property Proto: TWSProtocol read FProto;
    property Id: NativeUInt read GetId;
  end;

  TWSServerMessage = procedure(AConn: TWSConnection; AText: Boolean;
    P: PByte; Len: NativeInt) of object;
  TWSServerNotify = procedure(AConn: TWSConnection) of object;

  // Answer a plain HTTP request on the WebSocket port (see
  // TWSServer.OnPlainRequest). AHS carries the request as parsed by
  // WS.Handshake — Method, Path (the request-target) and Host are
  // filled; the WebSocket-only fields are not meaningful here.
  //
  // Path is the request-target exactly as received, NOT normalised. RFC
  // 7230 §5.3.2 lets a client send absolute-form ('GET
  // http://host/x HTTP/1.1', which proxies do and any client may), so a
  // hook that matches on Path must either accept absolute-form or
  // reject what it does not recognise — comparing Path = '/x' alone
  // will silently miss those requests.
  //
  // ARawRequest is exactly this request's header block (request line
  // through the terminating blank line) and nothing pipelined behind
  // it; query further headers with WS.Handshake.HeaderValue. Return
  // True with AResponse holding a complete HTTP/1.1 response — status
  // line, headers, body — and the bytes are written verbatim, then the
  // connection is closed (include a 'Connection: close' header so
  // well-behaved clients expect that). Return False (AResponse ignored)
  // for the standard refusal.
  //
  // Returning True with an EMPTY AResponse is treated as False: an
  // empty response would put a bare connection close on the wire,
  // indistinguishable from a network fault, so the standard refusal is
  // sent instead. An exception escaping the hook is likewise treated as
  // False — it is swallowed and the standard refusal is sent, so one
  // misbehaving handler cannot leak the connection or take down the
  // transport's execution context.
  TWSPlainRequestEvent = function(const AHS: TWSServerHandshake;
    const ARawRequest: RawByteString;
    out AResponse: RawByteString): Boolean of object;

  // Veto point on the opening handshake (see TWSServer.OnUpgradeRequest).
  // AHS is the request as parsed by WS.Handshake — Path, Host, Origin,
  // Protocols and the negotiated Deflate are filled; ARawRequest is
  // exactly this request's header block (request line through the
  // terminating blank line) and nothing pipelined behind it, so any
  // other header can be read with WS.Handshake.HeaderValue. Return True
  // to accept: the 101 follows and OnOpen fires as usual. Return False
  // to refuse: the server writes a 403 carrying AReason as its body
  // ('forbidden' when AReason is left empty) and closes the connection;
  // OnOpen and OnClientClose never fire for it. An exception escaping
  // the hook is swallowed and treated as False — one misbehaving
  // handler must not leak the connection or take down the transport's
  // execution context.
  TWSUpgradeRequestEvent = function(const AHS: TWSServerHandshake;
    const ARawRequest: RawByteString; out AReason: string): Boolean of object;

  TWSServer = class
  private
    FTransport: TWSTransport;
    FAllowDeflate: Boolean;
    FMaxMessage: NativeInt;
    FRegistry: array of TWSConnection;
    FRegistryCount: Integer;
    FLock: TCriticalSection;
    FOnMessage: TWSServerMessage;
    FOnOpen, FOnClose: TWSServerNotify;
    FOnPlainRequest: TWSPlainRequestEvent;
    FOnUpgradeRequest: TWSUpgradeRequestEvent;
    FMaxPendingOutput: NativeInt;
    FMaxConnections: Integer;
    FHandshakeTimeoutMs: Integer;
    FCloseTimeoutMs: Integer;
    FIdleTimeoutMs: Integer;
    FPingIntervalMs: Integer;
    FSweeper: TThread;
    FSweepWake: TEvent;

    procedure RegistryAdd(AConn: TWSConnection);
    procedure SweepClocks;
    procedure RegistryRemove(AConn: TWSConnection);
    procedure ReleaseConn(AConn: TWSConnection);
    // Caller-initiated teardown; returns False so drop sites can chain
    // "Exit(DropConn(...))". The connection is freed on return — or,
    // mid-delivery, as soon as the delivery site unwinds (deferred).
    function DropConn(AConn: TWSConnection): Boolean;
    // Hands pending protocol output to the transport. False = the
    // connection died and was dropped.
    function FlushConn(AConn: TWSConnection): Boolean;
    function FinishHandshake(AConn: TWSConnection; AHdrEnd: Integer): Boolean;
    function IngestAndFlush(AConn: TWSConnection; P: PByte;
      ALen: NativeInt): Boolean;

    // Post rendezvous: validates AConn against the registry under the
    // registry lock, then hands the transport a connection-id-keyed
    // envelope — never a connection pointer a foreign thread could
    // race against a free.
    procedure PostToConn(AConn: TWSConnection; AProc: TWSConnProc);

    procedure HandleAccept(ATConn: TWSTransportConn);
    procedure HandleData(ATConn: TWSTransportConn; P: PByte; ALen: NativeInt);
    procedure HandleSendReady(ATConn: TWSTransportConn);
    procedure HandleClosed(ATConn: TWSTransportConn);
    procedure HandlePost(ATConn: TWSTransportConn; AData: Pointer);
    function GetPort: Word;
  public
    // ABindAddress selects the listening interface: '' (the default)
    // binds every interface exactly as before; an IPv4 dotted-quad
    // ('127.0.0.1') or an IPv6 literal without brackets ('::1') binds
    // that one address, choosing the socket family from the literal.
    // Anything else — a hostname, brackets, a zone id — raises here
    // with a message naming the address; names are never resolved.
    // Port 0 still means kernel-assigned, read back through Port.
    constructor Create(APort: Word; AAllowDeflate: Boolean = True;
      AMaxMessage: NativeInt = 16 * 1024 * 1024;
      const ABindAddress: string = ''); overload;
    constructor Create(APort: Word; const ATls: TWSTransportTls;
      AAllowDeflate: Boolean = True;
      AMaxMessage: NativeInt = 16 * 1024 * 1024;
      const ABindAddress: string = ''); overload;
    destructor Destroy; override;

    // Blocks. ATimeoutMs >= 0 returns after one completion round (test
    // use); -1 loops until Stop.
    procedure Run(ATimeoutMs: Integer = -1);
    procedure Stop;

    property Port: Word read GetPort;

    // Resource bounds. Every one of these is judged on the connection's
    // own execution context, so a change takes effect for connections
    // whose next event lands after it; set them before Run for clarity.
    //
    // Bytes of protocol output one connection may hold unsent — frames
    // the transport has not yet taken because the peer is not reading.
    // Crossing it drops the connection (no close frame: a peer that is
    // not reading would never see one). Without this a peer that floods
    // pings, or echoes, and never reads grows the queue at line rate.
    // Default 4 x the message cap, floor 1 MiB: one cap-sized message
    // plus a few behind it is normal backpressure, more is a peer that
    // has stopped. 0 = unbounded (the pre-0.5.0 behaviour).
    property MaxPendingOutput: NativeInt
      read FMaxPendingOutput write FMaxPendingOutput;
    // Live connections, handshaking ones included. An accept beyond
    // the cap is closed at once, before any session state exists —
    // no handshake, no OnOpen, no OnClientClose. 0 = unbounded
    // (default; the OS descriptor limit is then the only ceiling).
    property MaxConnections: Integer
      read FMaxConnections write FMaxConnections;
    // Milliseconds from accept until the 101 has been handed to the
    // transport. A peer that connects and trickles (or says nothing) is
    // dropped when it lapses, silently — OnOpen never fired. The
    // plaintext counterpart of TWSTransportTls.HandshakeDeadlineMs,
    // which on a TLS listener only covers the TLS handshake; this clock
    // runs after it, over the HTTP upgrade. Default 10 s; 0 = never.
    property HandshakeTimeoutMs: Integer
      read FHandshakeTimeoutMs write FHandshakeTimeoutMs;
    // Milliseconds a peer gets to finish what the server is waiting on
    // at the end of a connection: answer a Close, or read a response
    // (403, plain-HTTP answer, protocol-error close frame) that is
    // draining ahead of the drop. Lapsing drops the connection.
    // Default 10 s; 0 = never.
    property CloseTimeoutMs: Integer
      read FCloseTimeoutMs write FCloseTimeoutMs;
    // Milliseconds without a single byte from the peer after which an
    // open connection is closed (1001 is queued best-effort, then it is
    // dropped; OnClientClose fires). Pongs count as bytes, so pair this
    // with PingIntervalMs to keep a live-but-quiet peer open. Default
    // 0 = never: idle connections are legitimate for many hosts.
    property IdleTimeoutMs: Integer
      read FIdleTimeoutMs write FIdleTimeoutMs;
    // Milliseconds of quiet after which the server pings the peer; the
    // pong (or any other byte) resets the quiet clock. Default 0 =
    // never ping. Meaningful mostly together with IdleTimeoutMs, where
    // it turns "no traffic" into "no pong": IdleTimeoutMs should then
    // exceed PingIntervalMs by a round trip.
    property PingIntervalMs: Integer
      read FPingIntervalMs write FPingIntervalMs;

    property OnMessage: TWSServerMessage read FOnMessage write FOnMessage;
    property OnOpen: TWSServerNotify read FOnOpen write FOnOpen;
    // Fires exactly once for every connection that saw OnOpen: when the
    // peer goes away, when the server drops it, and — for connections
    // still open at the time — from TWSServer.Destroy, on the thread
    // calling Destroy once the transport is quiesced (there, sends,
    // Close and Post on any connection report the drop). Sends inside
    // the handler report False (the connection is already being torn
    // down). An exception escaping the handler is treated like one from
    // OnOpen or OnMessage, but only after the session connection has been
    // released (and, on a plaintext listener, its socket closed): on the
    // epoll and IOCP transports it propagates out of Run; on
    // Network.framework, where callbacks run on GCD threads, an escaping
    // exception terminates the process, as it does from any callback.
    // During Destroy it is swallowed so shutdown completes.
    property OnClientClose: TWSServerNotify read FOnClose write FOnClose;
    // Opt-in single-port fallback: fired for a well-formed, body-less
    // HTTP request (GET or HEAD without Content-Length or
    // Transfer-Encoding) that is not a WebSocket upgrade attempt.
    // Upgrade attempts (valid or broken), malformed requests, and
    // requests advertising a body all keep the standard refusal —
    // as does everything when the property is unset. Single-shot: the
    // response is written, then the connection closes; there is no
    // keep-alive loop, no routing, no file serving. Fires on the
    // connection's execution context like every other callback
    // (ADR-0003): the Run thread on Linux/Windows, the connection's
    // dispatch queue on macOS. On a TLS listener the request arrives
    // already decrypted, exactly like handshake bytes.
    property OnPlainRequest: TWSPlainRequestEvent
      read FOnPlainRequest write FOnPlainRequest;
    // Opt-in handshake veto: fired for every well-formed upgrade request
    // after WS.Handshake accepted it and before the 101 is queued — the
    // place for Origin allow-lists, identity headers and the like.
    // Malformed requests never reach it (they get the standard 400 or,
    // when eligible, OnPlainRequest). Unset = accept everything,
    // unchanged behaviour. Fires on the connection's execution context
    // like every other callback (ADR-0003): the Run thread on
    // Linux/Windows, the connection's dispatch queue on macOS. On a TLS
    // listener the request arrives already decrypted.
    property OnUpgradeRequest: TWSUpgradeRequestEvent
      read FOnUpgradeRequest write FOnUpgradeRequest;
  end;

{$endif}

implementation

{$if defined(LINUX) or defined(DARWIN) or defined(WINDOWS)}

uses
  {$ifdef LINUX}
  WS.Transport.Epoll;
  {$endif}
  {$ifdef DARWIN}
  WS.Transport.NetworkFramework;
  {$endif}
  {$ifdef WINDOWS}
  WS.Transport.Iocp;
  {$endif}

const
  HandshakeMaxBytes = 16 * 1024;
  RegistryGrowth = 64;
  DefaultHandshakeTimeoutMs = 10000;
  DefaultCloseTimeoutMs = 10000;
  MinPendingOutput = 1024 * 1024;
  PendingOutputFactor = 4;
  // How often the sweeper looks for lapsed clocks. Coarse on purpose:
  // every deadline here is seconds long, and the walk is a lock plus
  // one compare per live connection.
  SweepIntervalMs = 100;

type
  // The one thread the session layer owns. It never touches a
  // connection: it reads each one's FSweepAt under the registry lock
  // and, for any that has lapsed, Posts CheckClock onto that
  // connection's execution context — the seam's cross-thread hook —
  // where the real judgement and any drop happen with the ordinary
  // per-connection serialization (ADR-0003).
  TWSSweeper = class(TThread)
  private
    FServer: TWSServer;
  protected
    procedure Execute; override;
  end;

  // What travels through the transport's SubmitPost: a method pointer
  // is two pointers, one too many for the opaque AData slot.
  PWSPostEnvelope = ^TWSPostEnvelope;
  TWSPostEnvelope = record
    Proc: TWSConnProc;
  end;

function NewEnvelope(AProc: TWSConnProc): PWSPostEnvelope;
begin
  New(Result);
  Result^.Proc := AProc;
end;

{ TWSConnection }

constructor TWSConnection.Create;
begin
  inherited;
  // The sentinel lives in the type, not in a caller: a zero-initialized
  // index would alias registry slot 0 and let an unregistered
  // connection validate against — and swap-remove — someone else's.
  FRegistryIndex := -1;
end;

destructor TWSConnection.Destroy;
begin
  FProto.Free;
  inherited;
end;

function TWSConnection.GetId: NativeUInt;
begin
  Result := FId;
end;

procedure TWSConnection.Reschedule;
begin
  if (FDeadline = 0) or ((FPingDue <> 0) and (FPingDue < FDeadline)) then
    FSweepAt := FPingDue
  else
    FSweepAt := FDeadline;
end;

procedure TWSConnection.ArmDeadline(AMs: Integer);
begin
  if AMs > 0 then
    FDeadline := GetTickCount64 + QWord(AMs)
  else
    FDeadline := 0;
  Reschedule;
end;

// Bytes arrived from the peer: an open connection's idle and ping
// clocks restart from now. Waiting states (handshake, close, drain)
// keep their deadline — progress there is judged by state changes,
// not by traffic, or a trickling peer could extend them forever.
procedure TWSConnection.NoteActivity;
var
  Now_: QWord;
begin
  if FState <> wcsOpen then Exit;
  Now_ := GetTickCount64;
  if FServer.FIdleTimeoutMs > 0 then
    FDeadline := Now_ + QWord(FServer.FIdleTimeoutMs)
  else
    FDeadline := 0;
  if FServer.FPingIntervalMs > 0 then
    FPingDue := Now_ + QWord(FServer.FPingIntervalMs)
  else
    FPingDue := 0;
  Reschedule;
end;

// Posted by the sweeper; runs on this connection's execution context.
// AConn is Self (the Post signature), kept for the method-pointer shape.
procedure TWSConnection.CheckClock(AConn: TWSConnection);
var
  Now_: QWord;
begin
  FSweepPosted := False;
  if FDropping then Exit;
  Now_ := GetTickCount64;
  if (FDeadline <> 0) and (Now_ >= FDeadline) then
  begin
    FDeadline := 0;
    case FState of
      wcsHandshake:
        FServer.DropConn(Self); // never opened: silent, like a 403
      wcsOpen:
        begin
          // Idle: say goodbye in case the peer is merely quiet, then go
          // without waiting for the echo — a peer that has fallen off
          // the network is the common case here.
          FProto.SendClose(1001, 'idle timeout');
          FState := wcsClosing;
          if FServer.FlushConn(Self) then FServer.DropConn(Self);
        end;
      wcsClosing:
        FServer.DropConn(Self);
    end;
    Exit;
  end;
  if (FPingDue <> 0) and (Now_ >= FPingDue) then
  begin
    // One ping per quiet period: the next is scheduled by the peer's
    // reply (NoteActivity), not by the clock, so an unanswered ping
    // simply lets the idle deadline run out.
    FPingDue := 0;
    Reschedule;
    if FState = wcsOpen then
    begin
      FProto.SendPing(nil, 0);
      FServer.FlushConn(Self);
    end;
  end;
end;

procedure TWSConnection.ProtoMessage(AText: Boolean; P: PByte; ALen: NativeInt);
begin
  // A send inside an earlier OnMessage of this same ingest run may have
  // found the connection dead; the drop is deferred (see DropConn) and
  // the remaining messages of the run are not the application's to see.
  if FDropDeferred then Exit;
  if Assigned(FServer.FOnMessage) then
    FServer.FOnMessage(Self, AText, P, ALen);
end;

function TWSConnection.SendText(P: PByte; ALen: NativeInt): Boolean;
begin
  // Teardown already running (an OnClientClose handler sending into the
  // connection it is being told about): the transport side is gone, so
  // report the drop without touching it — a flush here would re-enter
  // DropConn and free the object a second time.
  if FDropping then Exit(False);
  Result := True;
  if FState = wcsOpen then
  begin
    FProto.SendText(P, ALen);
    Result := FServer.FlushConn(Self);
  end;
end;

function TWSConnection.SendBinary(P: PByte; ALen: NativeInt): Boolean;
begin
  if FDropping then Exit(False);
  Result := True;
  if FState = wcsOpen then
  begin
    FProto.SendBinary(P, ALen);
    Result := FServer.FlushConn(Self);
  end;
end;

procedure TWSConnection.Post(AProc: TWSConnProc);
begin
  FServer.PostToConn(Self, AProc);
end;

function TWSConnection.Close(ACode: Word; const AReason: string): Boolean;
begin
  if FDropping then Exit(False);
  Result := True;
  if FState = wcsOpen then
  begin
    FProto.SendClose(ACode, AReason);
    FState := wcsClosing;
    FPingDue := 0;
    ArmDeadline(FServer.FCloseTimeoutMs);
    Result := FServer.FlushConn(Self);
  end;
end;

{ TWSServer }

constructor TWSServer.Create(APort: Word; AAllowDeflate: Boolean;
  AMaxMessage: NativeInt; const ABindAddress: string);
begin
  Create(APort, WSTransportNoTls, AAllowDeflate, AMaxMessage, ABindAddress);
end;

constructor TWSServer.Create(APort: Word; const ATls: TWSTransportTls;
  AAllowDeflate: Boolean; AMaxMessage: NativeInt; const ABindAddress: string);
begin
  inherited Create;
  FAllowDeflate := AAllowDeflate;
  FMaxMessage := AMaxMessage;
  FMaxPendingOutput := AMaxMessage * PendingOutputFactor;
  if FMaxPendingOutput < MinPendingOutput then
    FMaxPendingOutput := MinPendingOutput;
  FHandshakeTimeoutMs := DefaultHandshakeTimeoutMs;
  FCloseTimeoutMs := DefaultCloseTimeoutMs;
  FLock := TCriticalSection.Create;
  FSweepWake := TEvent.Create(nil, False, False, '');
  {$ifdef LINUX}
  FTransport := TWSEpollTransport.Create(APort, ATls, ABindAddress);
  {$endif}
  {$ifdef DARWIN}
  FTransport := TWSNetworkFrameworkTransport.Create(APort, ATls, ABindAddress);
  {$endif}
  {$ifdef WINDOWS}
  FTransport := TWSIocpTransport.Create(APort, ATls, ABindAddress);
  {$endif}
  FTransport.OnAccept := HandleAccept;
  FTransport.OnData := HandleData;
  FTransport.OnSendReady := HandleSendReady;
  FTransport.OnClosed := HandleClosed;
  FTransport.OnPost := HandlePost;
  FTransport.Open;
  FSweeper := TWSSweeper.Create(True);
  TWSSweeper(FSweeper).FServer := Self;
  FSweeper.Start;
end;

destructor TWSServer.Destroy;
var
  Open: array of TWSConnection;
  I: Integer;
begin
  // Quiesce the transport first: after Shutdown returns, no completion
  // can fire on any thread and every transport connection object is
  // gone — freeing the session connections is genuinely
  // single-threaded. (Callbacks racing the shutdown ran to completion
  // against still-valid state.) The nil guard keeps a transport
  // constructor failure from masking its own exception when FPC runs
  // this destructor on the partially constructed server.
  // The sweeper goes first: once it has joined, no new post can be
  // issued from this side, and the transport drain below settles the
  // ones in flight.
  if FSweeper <> nil then
  begin
    FSweeper.Terminate;
    FSweepWake.SetEvent;
    FSweeper.WaitFor;
    FSweeper.Free;
  end;
  if FTransport <> nil then
  begin
    FTransport.Shutdown;
    // Connections still open get their OnClientClose here, so every
    // OnOpen is paired and a handler holding references (the Post
    // lifetime contract) learns they are gone. The transport is
    // quiesced and has freed its connection objects, so first detach
    // every session connection from it at once: marked dropping (sends
    // and Close report False), out of the registry (Post drops), FTConn
    // cleared. Only then run the handlers — one may reach any other
    // connection (a "user left" broadcast), not just its own.
    FLock.Acquire;
    try
      Open := Copy(FRegistry, 0, FRegistryCount);
      FRegistryCount := 0;
    finally
      FLock.Release;
    end;
    for I := 0 to High(Open) do
    begin
      Open[I].FRegistryIndex := -1;
      Open[I].FDropping := True;
      Open[I].FTConn := nil;
    end;
    for I := 0 to High(Open) do
      try
        ReleaseConn(Open[I]);
      except
        // A destructor has to finish: the connection was released by
        // ReleaseConn's finally; the handler's exception is dropped.
        on Exception do;
      end;
    FTransport.Free;
  end;
  FSweepWake.Free;
  FLock.Free;
  inherited;
end;

{ TWSSweeper }

procedure TWSSweeper.Execute;
begin
  while not Terminated do
  begin
    FServer.FSweepWake.WaitFor(SweepIntervalMs);
    if Terminated then Break;
    FServer.SweepClocks;
  end;
end;

procedure TWSServer.SweepClocks;
var
  I: Integer;
  Now_: QWord;
  Conn: TWSConnection;
begin
  Now_ := GetTickCount64;
  FLock.Acquire;
  try
    for I := 0 to FRegistryCount - 1 do
    begin
      Conn := FRegistry[I];
      if (Conn.FSweepAt = 0) or (Now_ < Conn.FSweepAt) or
        Conn.FSweepPosted then Continue;
      Conn.FSweepPosted := True;
      // Same rendezvous PostToConn performs, done inline because the
      // lock is already held: only the transport-neutral id crosses to
      // the connection's context.
      FTransport.SubmitPost(Conn.FId, NewEnvelope(Conn.CheckClock));
    end;
  finally
    FLock.Release;
  end;
end;

procedure TWSServer.RegistryAdd(AConn: TWSConnection);
begin
  FLock.Acquire;
  try
    if FRegistryCount = Length(FRegistry) then
      SetLength(FRegistry, FRegistryCount + RegistryGrowth);
    FRegistry[FRegistryCount] := AConn;
    AConn.FRegistryIndex := FRegistryCount;
    Inc(FRegistryCount);
  finally
    FLock.Release;
  end;
end;

procedure TWSServer.RegistryRemove(AConn: TWSConnection);
var
  I: Integer;
begin
  FLock.Acquire;
  try
    I := AConn.FRegistryIndex;
    // Not registered (already removed, or never added): nothing to do —
    // the same no-op the old full scan produced on a miss.
    if (I < 0) or (I >= FRegistryCount) or (FRegistry[I] <> AConn) then Exit;
    // Swap-remove; the connection moved into the hole learns its new
    // slot, or the hole WAS the tail and nothing moved.
    FRegistry[I] := FRegistry[FRegistryCount - 1];
    FRegistry[FRegistryCount - 1] := nil;
    if FRegistry[I] <> nil then
      FRegistry[I].FRegistryIndex := I;
    Dec(FRegistryCount);
    AConn.FRegistryIndex := -1;
  finally
    FLock.Release;
  end;
end;

// Shared teardown tail: unregister, notify (post-handshake conns only),
// free the session object.
procedure TWSServer.ReleaseConn(AConn: TWSConnection);
begin
  RegistryRemove(AConn);
  // A raising OnClientClose still releases the connection; the
  // exception carries on to the caller.
  try
    if (AConn.FState <> wcsHandshake) and Assigned(FOnClose) then
      FOnClose(AConn);
  finally
    AConn.Free;
  end;
end;

procedure TWSServer.PostToConn(AConn: TWSConnection; AProc: TWSConnProc);
var
  TransportId: NativeUInt;
  Live: Boolean;
  Idx: Integer;
begin
  // Nothing to schedule: an envelope carrying a nil proc would only
  // reach HandlePost and crash the connection's execution context.
  if not Assigned(AProc) then Exit;

  // Rendezvous under the registry lock. AConn.FRegistryIndex names the
  // connection's own slot, so validation is a single indexed compare
  // rather than a scan of every live connection — the documented
  // broadcast pattern (Post to each of N connections) was O(n^2) with
  // the accept path blocked behind the lock for the whole sweep.
  //
  // Why the dereference is safe: reading FRegistryIndex touches the
  // object, which the old scan deliberately did not do until it had
  // matched the pointer. It is contract-equivalent all the same. The
  // Post lifetime contract (see TWSConnection.Post) says a reference is
  // valid from OnOpen until your OnClientClose handler returns — inside
  // that window the object is allocated, so the read is a read of live
  // memory; the index may be stale (a concurrent drop can unregister
  // between our read and the compare) and the compare against
  // FRegistry[Idx] catches exactly that, under the lock, before we
  // touch anything else. Outside that window the caller has already
  // passed a dangling reference and the old scan was equally undefined:
  // it compared a freed pointer, and any match would have gone on to
  // dereference it. So the deref widens nothing the contract permits.
  //
  // Past this point only the transport-neutral id travels; the
  // transport revalidates it on the connection's own execution context,
  // so a drop that lands between here and delivery just discards the
  // post.
  TransportId := 0;
  FLock.Acquire;
  try
    Idx := AConn.FRegistryIndex;
    Live := (Idx >= 0) and (Idx < FRegistryCount) and (FRegistry[Idx] = AConn);
    if Live then
      TransportId := AConn.FId;
  finally
    FLock.Release;
  end;
  if not Live then Exit; // already gone: silently dropped
  FTransport.SubmitPost(TransportId, NewEnvelope(AProc));
end;

function TWSServer.DropConn(AConn: TWSConnection): Boolean;
var
  TConn: TWSTransportConn;
begin
  Result := False;
  // Mid-delivery (Ingest's frame loop, or OnOpen with the caller still
  // reading conn state afterwards) the object must not be freed under
  // its own stack — the use-after-free the win64 stress battery
  // caught. Defer: the callers' contract (False = do not touch the
  // reference again) already covers it, and the delivery site performs
  // the real teardown as soon as it unwinds.
  if AConn.FInDelivery then
  begin
    AConn.FDropDeferred := True;
    Exit;
  end;
  // Re-entrant drop — an OnClientClose handler sending into the dead
  // connection lands back here mid-teardown; a second ReleaseConn
  // would double-free.
  if AConn.FDropping then Exit;
  AConn.FDropping := True;
  TConn := AConn.FTConn;
  TConn.UserData := nil;
  // The transport side is closed even if OnClientClose raises: the
  // socket must not outlive the session object that owned it.
  try
    ReleaseConn(AConn);
  finally
    TConn.SubmitClose;
  end;
end;

function TWSServer.FlushConn(AConn: TWSConnection): Boolean;
var
  W: NativeInt;
begin
  Result := True;
  if AConn.FProto.OutPending = 0 then Exit;
  W := AConn.FTConn.SubmitSend(AConn.FProto.OutPtr, AConn.FProto.OutPending);
  if W < 0 then Exit(DropConn(AConn));
  AConn.FProto.OutConsume(W);
  // Anything still pending is backpressure: the transport fires
  // OnSendReady when it can take more — up to a point. Past the cap the
  // peer has stopped reading, and the only thing left to bound is our
  // memory.
  if (FMaxPendingOutput > 0) and (AConn.FProto.OutPending > FMaxPendingOutput) then
    Exit(DropConn(AConn));
end;

function TWSServer.FinishHandshake(AConn: TWSConnection;
  AHdrEnd: Integer): Boolean;
var
  HS: TWSServerHandshake;
  Resp, HdrBlock: RawByteString;
  Reason: string;
  Answered, Accepted: Boolean;
begin
  Result := False;
  // Parse THIS request only. AHdrEnd is the offset just past the
  // terminating blank line (HandshakeFindEnd), so with 1-based
  // RawByteString indexing Copy(FHsBuf, 1, AHdrEnd) is exactly the
  // header block. Handing the whole accumulator to the parser instead
  // folded a pipelined follow-up request's headers into this one (Host
  // came out as 'a, b') and let its Content-Length demote a legitimate
  // body-less GET from wrkPlain to wrkOther.
  HdrBlock := Copy(AConn.FHsBuf, 1, AHdrEnd);
  if not ServerParseRequest(HdrBlock, FAllowDeflate, HS) then
  begin
    // Single-port fallback: a well-formed body-less non-upgrade request
    // may be answered by the host (OnPlainRequest). The consumer's
    // bytes ride a fresh protocol out queue so a partial write shares
    // the standard backpressure/drain-then-drop path; the connection
    // closes once they are on the wire (single-shot, no keep-alive).
    Answered := False;
    if (HS.Kind = wrkPlain) and Assigned(FOnPlainRequest) then
      try
        // True with an empty response is treated as False: an empty
        // body would reach the client as a bare close, which it cannot
        // tell apart from a network fault. Send the standard refusal.
        Answered := FOnPlainRequest(HS, HdrBlock, Resp) and (Length(Resp) > 0);
      except
        // A raising hook is a False return, swallowed here. Letting it
        // escape would leave the connection half-built (FProto nil,
        // still registered until Destroy) and kill the transport's
        // execution context along with every other connection on it.
        Answered := False;
      end;
    if Answered then
    begin
      // HS.Deflate is Reset-default (Enabled=False) on every
      // non-upgrade path — ServerParseRequest negotiates only for a
      // validated upgrade — so this throwaway protocol object
      // allocates no deflater; it is here purely for the out queue.
      AConn.FProto := TWSProtocol.Create(wsrServer, HS.Deflate, FMaxMessage);
      AConn.FProto.QueueRaw(@Resp[1], Length(Resp));
      AConn.FHsBuf := '';
      AConn.FDropPending := True; // drop as soon as the response drains
      AConn.ArmDeadline(FCloseTimeoutMs);
      // Nested rather than `and`-ed: FlushConn returning False means the
      // connection was dropped and possibly freed, and the second test
      // would read OutPending out of it.
      if FlushConn(AConn) then
      begin
        if AConn.FProto.OutPending = 0 then
          DropConn(AConn);
      end;
      Exit;
    end;
    Resp := ServerBuildReject(400, HS.Failure);
    AConn.FTConn.SubmitSend(@Resp[1], Length(Resp)); // best effort
    Exit(DropConn(AConn));
  end;

  if Assigned(FOnUpgradeRequest) then
  begin
    try
      Accepted := FOnUpgradeRequest(HS, HdrBlock, Reason);
    except
      // A raising hook is a refusal, swallowed here — the same reasoning
      // as OnPlainRequest above: an escaping exception would leave the
      // connection half-built and take the execution context with it.
      Accepted := False;
    end;
    if not Accepted then
    begin
      if Reason = '' then Reason := 'forbidden';
      Resp := ServerBuildReject(403, Reason);
      // Same backpressure path as OnPlainRequest answers: queue the 403
      // through the protocol out buffer and drop once it drains. A bare
      // SubmitSend + DropConn can truncate under OnSendReady deferral.
      AConn.FProto := TWSProtocol.Create(wsrServer, HS.Deflate, FMaxMessage);
      AConn.FProto.QueueRaw(@Resp[1], Length(Resp));
      AConn.FHsBuf := '';
      AConn.FDropPending := True;
      AConn.ArmDeadline(FCloseTimeoutMs);
      if FlushConn(AConn) then
      begin
        if AConn.FProto.OutPending = 0 then
          DropConn(AConn);
      end;
      // Still wcsHandshake: no OnOpen ever fired, so no OnClientClose.
      Exit;
    end;
  end;

  AConn.FProto := TWSProtocol.Create(wsrServer, HS.Deflate, FMaxMessage);
  AConn.FProto.OnMessage := AConn.ProtoMessage;

  // Hand the 101 to the protocol's out queue so a partial send shares
  // the one backpressure path (ordered before any frame the open
  // handler queues).
  Resp := ServerBuildResponse(HS);
  AConn.FProto.QueueRaw(@Resp[1], Length(Resp));
  AConn.FHsBuf := '';
  // Open only once the 101 is on its way: a peer that resets right after
  // sending its request fails this flush, and the drop must not look
  // like a closed session to OnClientClose when OnOpen never ran.
  if not FlushConn(AConn) then Exit;
  AConn.FState := wcsOpen;
  AConn.NoteActivity;

  // Same deferral guard as the Ingest run: a send inside OnOpen may
  // find the peer dead, and the caller still reads Conn state after we
  // return — the drop must not free the object under it.
  AConn.FInDelivery := True;
  try
    if Assigned(FOnOpen) then FOnOpen(AConn);
  finally
    AConn.FInDelivery := False;
  end;
  if AConn.FDropDeferred then
  begin
    AConn.FDropDeferred := False;
    Exit(DropConn(AConn)); // False: the caller must not touch Conn
  end;
  Result := True;
end;

function TWSServer.IngestAndFlush(AConn: TWSConnection; P: PByte;
  ALen: NativeInt): Boolean;
var
  IngestOk: Boolean;
begin
  Result := False;
  // The guard makes DropConn defer while the protocol's frame loop is
  // live (a send inside OnMessage may find the peer dead with more
  // pipelined frames still unparsed); the deferred teardown runs here,
  // with Ingest unwound and the object safe to free.
  AConn.FInDelivery := True;
  try
    IngestOk := AConn.FProto.Ingest(P, ALen);
  finally
    AConn.FInDelivery := False;
  end;
  if AConn.FDropDeferred then
  begin
    AConn.FDropDeferred := False;
    Exit(DropConn(AConn));
  end;
  if not IngestOk then
  begin
    // Get the close frame out, then die. If a prior send is still in
    // flight the transport takes nothing now — defer the drop until
    // OnSendReady has drained the close frame, or it never reaches the
    // wire (races the 101 on fast loopback).
    if FlushConn(AConn) then
    begin
      if AConn.FProto.OutPending = 0 then
        DropConn(AConn)
      else
      begin
        AConn.FDropPending := True;
        AConn.ArmDeadline(FCloseTimeoutMs);
      end;
    end;
    Exit;
  end;
  if not FlushConn(AConn) then Exit;
  if AConn.FProto.CloseDone then
  begin
    if AConn.FProto.OutPending = 0 then
      Exit(DropConn(AConn));
    // Our close echo is stuck behind a peer that is not reading: give
    // it the close budget, not forever.
    AConn.FDropPending := True;
    AConn.ArmDeadline(FCloseTimeoutMs);
  end;
  Result := True;
end;

procedure TWSServer.HandleAccept(ATConn: TWSTransportConn);
var
  Conn: TWSConnection;
  Full: Boolean;
begin
  if FMaxConnections > 0 then
  begin
    FLock.Acquire;
    try
      Full := FRegistryCount >= FMaxConnections;
    finally
      FLock.Release;
    end;
    if Full then
    begin
      // Refused before any session state exists: the transport closes
      // it and no OnOpen/OnClientClose pair is owed to anyone.
      ATConn.SubmitClose;
      Exit;
    end;
  end;
  Conn := TWSConnection.Create;
  Conn.FServer := Self;
  Conn.FTConn := ATConn;
  Conn.FId := ATConn.Id;
  Conn.FState := wcsHandshake;
  Conn.ArmDeadline(FHandshakeTimeoutMs);
  ATConn.UserData := Conn;
  RegistryAdd(Conn);
end;

procedure TWSServer.HandleData(ATConn: TWSTransportConn; P: PByte;
  ALen: NativeInt);
var
  Conn: TWSConnection;
  Off, HdrEnd, LeftLen: Integer;
  Left: TBytes;
begin
  Conn := TWSConnection(ATConn.UserData);
  if Conn = nil then Exit;

  case Conn.FState of
    wcsHandshake:
      begin
        // A plain response is draining towards the drop; anything else
        // the client pipelines (it was told Connection: close) is
        // discarded.
        if Conn.FDropPending then Exit;
        Off := Length(Conn.FHsBuf);
        SetLength(Conn.FHsBuf, Off + ALen);
        Move(P^, Conn.FHsBuf[Off + 1], ALen);
        if Length(Conn.FHsBuf) > HandshakeMaxBytes then
        begin
          DropConn(Conn);
          Exit;
        end;
        HdrEnd := HandshakeFindEnd(Conn.FHsBuf);
        if HdrEnd = 0 then Exit;
        // Frames pipelined behind the request get replayed post-101.
        LeftLen := Length(Conn.FHsBuf) - HdrEnd;
        if LeftLen > 0 then
        begin
          SetLength(Left, LeftLen);
          Move(Conn.FHsBuf[HdrEnd + 1], Left[0], LeftLen);
        end;
        if not FinishHandshake(Conn, HdrEnd) then Exit;
        if (Conn.FState = wcsOpen) and (LeftLen > 0) then
          IngestAndFlush(Conn, @Left[0], LeftLen);
      end;
    wcsOpen, wcsClosing:
      begin
        Conn.NoteActivity;
        IngestAndFlush(Conn, P, ALen);
      end;
  end;
end;

procedure TWSServer.HandleSendReady(ATConn: TWSTransportConn);
var
  Conn: TWSConnection;
begin
  Conn := TWSConnection(ATConn.UserData);
  if Conn = nil then Exit;
  // The TLS transports report send-ready after their own handshake
  // flight completes, before any HTTP upgrade has been parsed: nothing
  // is queued yet and no protocol object exists to flush.
  if Conn.FProto = nil then Exit;
  if not FlushConn(Conn) then Exit;
  if Conn.FDropPending and (Conn.FProto.OutPending = 0) then
  begin
    DropConn(Conn);
    Exit;
  end;
  if Conn.FProto.CloseDone and (Conn.FProto.OutPending = 0) then
    DropConn(Conn);
end;

procedure TWSServer.HandleClosed(ATConn: TWSTransportConn);
var
  Conn: TWSConnection;
begin
  Conn := TWSConnection(ATConn.UserData);
  if Conn = nil then Exit;
  ATConn.UserData := nil;
  // Same teardown marker DropConn sets: a send or Close inside the
  // OnClientClose handler must return False, not flush into the dead
  // transport connection and release the session object a second time.
  Conn.FDropping := True;
  ReleaseConn(Conn);
  // The transport frees ATConn after this callback returns.
end;

procedure TWSServer.HandlePost(ATConn: TWSTransportConn; AData: Pointer);
var
  Env: PWSPostEnvelope;
  Conn: TWSConnection;
begin
  Env := PWSPostEnvelope(AData);
  try
    if ATConn = nil then Exit; // dropped in transit (conn gone/shutdown)
    Conn := TWSConnection(ATConn.UserData);
    if Conn = nil then Exit;   // session already let go of it
    // AProc may legitimately end with the connection dropped and freed
    // (a Send returning False); nothing below touches Conn again.
    // PostToConn already refuses a nil proc; re-check here so a stray
    // envelope can never turn into a call through a nil code pointer.
    if Assigned(Env^.Proc) then
      Env^.Proc(Conn);
  finally
    Dispose(Env);
  end;
end;

function TWSServer.GetPort: Word;
begin
  Result := FTransport.Port;
end;

procedure TWSServer.Run(ATimeoutMs: Integer);
begin
  FTransport.Run(ATimeoutMs);
end;

procedure TWSServer.Stop;
begin
  FTransport.Stop;
end;

{$endif}

end.
