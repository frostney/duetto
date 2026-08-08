unit WS.Server;

// Platform-neutral WebSocket server session layer. Per connection: a
// TWSProtocol does every byte of RFC 6455; this unit only moves bytes
// between the platform transport (WS.Transport, selected per platform
// below) and that machine. Handshakes are accumulated until the blank
// line, parsed by WS.Handshake, answered, and the connection flips from
// "handshaking" to "open". A well-formed non-upgrade request may
// instead be answered by the host via OnPlainRequest (single-shot,
// then close); with the hook unset it is refused exactly as before.
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
    // Own slot in FServer.FRegistry, or -1 when unregistered (set at
    // construction, before the object is reachable). Once registered,
    // written and read only under FServer.FLock; makes the Post
    // rendezvous O(1) instead of a scan of every live connection.
    FRegistryIndex: Integer;
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
    // layer, not here.
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

    procedure RegistryAdd(AConn: TWSConnection);
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
    constructor Create(APort: Word; AAllowDeflate: Boolean = True;
      AMaxMessage: NativeInt = 16 * 1024 * 1024); overload;
    constructor Create(APort: Word; const ATls: TWSTransportTls;
      AAllowDeflate: Boolean = True;
      AMaxMessage: NativeInt = 16 * 1024 * 1024); overload;
    destructor Destroy; override;

    // Blocks. ATimeoutMs >= 0 returns after one completion round (test
    // use); -1 loops until Stop.
    procedure Run(ATimeoutMs: Integer = -1);
    procedure Stop;

    property Port: Word read GetPort;
    property OnMessage: TWSServerMessage read FOnMessage write FOnMessage;
    property OnOpen: TWSServerNotify read FOnOpen write FOnOpen;
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

type
  // What travels through the transport's SubmitPost: a method pointer
  // is two pointers, one too many for the opaque AData slot.
  PWSPostEnvelope = ^TWSPostEnvelope;
  TWSPostEnvelope = record
    Proc: TWSConnProc;
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
  Result := FTConn.Id;
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
  Result := True;
  if FState = wcsOpen then
  begin
    FProto.SendText(P, ALen);
    Result := FServer.FlushConn(Self);
  end;
end;

function TWSConnection.SendBinary(P: PByte; ALen: NativeInt): Boolean;
begin
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
  Result := True;
  if FState = wcsOpen then
  begin
    FProto.SendClose(ACode, AReason);
    FState := wcsClosing;
    Result := FServer.FlushConn(Self);
  end;
end;

{ TWSServer }

constructor TWSServer.Create(APort: Word; AAllowDeflate: Boolean;
  AMaxMessage: NativeInt);
begin
  Create(APort, WSTransportNoTls, AAllowDeflate, AMaxMessage);
end;

constructor TWSServer.Create(APort: Word; const ATls: TWSTransportTls;
  AAllowDeflate: Boolean; AMaxMessage: NativeInt);
begin
  inherited Create;
  FAllowDeflate := AAllowDeflate;
  FMaxMessage := AMaxMessage;
  FLock := TCriticalSection.Create;
  {$ifdef LINUX}
  FTransport := TWSEpollTransport.Create(APort, ATls);
  {$endif}
  {$ifdef DARWIN}
  FTransport := TWSNetworkFrameworkTransport.Create(APort, ATls);
  {$endif}
  {$ifdef WINDOWS}
  FTransport := TWSIocpTransport.Create(APort, ATls);
  {$endif}
  FTransport.OnAccept := HandleAccept;
  FTransport.OnData := HandleData;
  FTransport.OnSendReady := HandleSendReady;
  FTransport.OnClosed := HandleClosed;
  FTransport.OnPost := HandlePost;
  FTransport.Open;
end;

destructor TWSServer.Destroy;
var
  I: Integer;
begin
  // Quiesce the transport first: after Shutdown returns, no completion
  // can fire on any thread and every transport connection object is
  // gone — freeing the session connections is genuinely
  // single-threaded. (Callbacks racing the shutdown ran to completion
  // against still-valid state.) The nil guard keeps a transport
  // constructor failure from masking its own exception when FPC runs
  // this destructor on the partially constructed server.
  if FTransport <> nil then
  begin
    FTransport.Shutdown;
    for I := 0 to FRegistryCount - 1 do
      FRegistry[I].Free;
    FTransport.Free;
  end;
  FLock.Free;
  inherited;
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
  if (AConn.FState <> wcsHandshake) and Assigned(FOnClose) then
    FOnClose(AConn);
  AConn.Free;
end;

procedure TWSServer.PostToConn(AConn: TWSConnection; AProc: TWSConnProc);
var
  Env: PWSPostEnvelope;
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
      TransportId := AConn.FTConn.Id;
  finally
    FLock.Release;
  end;
  if not Live then Exit; // already gone: silently dropped
  New(Env);
  Env^.Proc := AProc;
  FTransport.SubmitPost(TransportId, Env);
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
  ReleaseConn(AConn);
  TConn.SubmitClose;
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
  // OnSendReady when it can take more.
end;

function TWSServer.FinishHandshake(AConn: TWSConnection;
  AHdrEnd: Integer): Boolean;
var
  HS: TWSServerHandshake;
  Resp, HdrBlock: RawByteString;
  Answered: Boolean;
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

  AConn.FProto := TWSProtocol.Create(wsrServer, HS.Deflate, FMaxMessage);
  AConn.FProto.OnMessage := AConn.ProtoMessage;

  // Hand the 101 to the protocol's out queue so a partial send shares
  // the one backpressure path (ordered before any frame the open
  // handler queues).
  Resp := ServerBuildResponse(HS);
  AConn.FProto.QueueRaw(@Resp[1], Length(Resp));
  AConn.FState := wcsOpen;
  AConn.FHsBuf := '';
  if not FlushConn(AConn) then Exit;

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
        AConn.FDropPending := True;
    end;
    Exit;
  end;
  if not FlushConn(AConn) then Exit;
  if AConn.FProto.CloseDone and (AConn.FProto.OutPending = 0) then
    Exit(DropConn(AConn));
  Result := True;
end;

procedure TWSServer.HandleAccept(ATConn: TWSTransportConn);
var
  Conn: TWSConnection;
begin
  Conn := TWSConnection.Create;
  Conn.FServer := Self;
  Conn.FTConn := ATConn;
  Conn.FState := wcsHandshake;
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
      IngestAndFlush(Conn, P, ALen);
  end;
end;

procedure TWSServer.HandleSendReady(ATConn: TWSTransportConn);
var
  Conn: TWSConnection;
begin
  Conn := TWSConnection(ATConn.UserData);
  if Conn = nil then Exit;
  if not FlushConn(Conn) then Exit;
  if Conn.FProto <> nil then
  begin
    if Conn.FDropPending and (Conn.FProto.OutPending = 0) then
    begin
      DropConn(Conn);
      Exit;
    end;
    if Conn.FProto.CloseDone and (Conn.FProto.OutPending = 0) then
      DropConn(Conn);
  end;
end;

procedure TWSServer.HandleClosed(ATConn: TWSTransportConn);
var
  Conn: TWSConnection;
begin
  Conn := TWSConnection(ATConn.UserData);
  if Conn = nil then Exit;
  ATConn.UserData := nil;
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
