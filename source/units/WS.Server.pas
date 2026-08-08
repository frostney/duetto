unit WS.Server;

// Platform-neutral WebSocket server session layer. Per connection: a
// TWSProtocol does every byte of RFC 6455; this unit only moves bytes
// between the platform transport (WS.Transport, selected per platform
// below) and that machine. Handshakes are accumulated until the blank
// line, parsed by WS.Handshake, answered, and the connection flips from
// "handshaking" to "open".
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
    FDropPending: Boolean;     // protocol failed; drop once output drains
    procedure ProtoMessage(AText: Boolean; P: PByte; ALen: NativeInt);
    function GetId: NativeUInt;
  public
    UserData: Pointer;
    destructor Destroy; override;
    // Callable from this connection's callback context (ADR-0003).
    // False = the transport reported the connection dead during the
    // flush: the connection was dropped and freed before the call
    // returned (no OnClientClose follows) and the reference is
    // dangling — it must not be touched again. True = the connection
    // is still alive, including the no-op cases (not yet open, already
    // closing). This matches the pre-seam reactor's drop semantics;
    // ignoring the result is legal Pascal and keeps old callers valid.
    function SendText(P: PByte; ALen: NativeInt): Boolean;
    function SendBinary(P: PByte; ALen: NativeInt): Boolean;
    // Same mid-call drop can occur here (unreported): if the transport
    // declares the connection dead while the close frame flushes, the
    // connection is freed before Close returns.
    procedure Close(ACode: Word = 1000; const AReason: string = '');
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
    // or racing TWSServer.Destroy, is undefined behaviour.
    procedure Post(AProc: TWSConnProc);
    property Proto: TWSProtocol read FProto;
    property Id: NativeUInt read GetId;
  end;

  TWSServerMessage = procedure(AConn: TWSConnection; AText: Boolean;
    P: PByte; Len: NativeInt) of object;
  TWSServerNotify = procedure(AConn: TWSConnection) of object;

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

    procedure RegistryAdd(AConn: TWSConnection);
    procedure RegistryRemove(AConn: TWSConnection);
    procedure ReleaseConn(AConn: TWSConnection);
    // Caller-initiated teardown; returns False so drop sites can chain
    // "Exit(DropConn(...))". The connection is freed on return.
    function DropConn(AConn: TWSConnection): Boolean;
    // Hands pending protocol output to the transport. False = the
    // connection died and was dropped.
    function FlushConn(AConn: TWSConnection): Boolean;
    function FinishHandshake(AConn: TWSConnection): Boolean;
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

procedure TWSConnection.Close(ACode: Word; const AReason: string);
begin
  if FState = wcsOpen then
  begin
    FProto.SendClose(ACode, AReason);
    FState := wcsClosing;
    FServer.FlushConn(Self);
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
    for I := 0 to FRegistryCount - 1 do
      if FRegistry[I] = AConn then
      begin
        FRegistry[I] := FRegistry[FRegistryCount - 1];
        FRegistry[FRegistryCount - 1] := nil;
        Dec(FRegistryCount);
        Break;
      end;
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
  TId: NativeUInt;
  Live: Boolean;
  I: Integer;
begin
  // Rendezvous under the registry lock: pointer-compare first — a
  // dropping connection is unregistered before it is freed, and the
  // free cannot start while we hold the lock — and dereference only a
  // connection that is provably still registered. Past this point only
  // the transport-neutral id travels; the transport revalidates it on
  // the connection's own execution context, so a drop that lands
  // between here and delivery just discards the post.
  TId := 0;
  Live := False;
  FLock.Acquire;
  try
    for I := 0 to FRegistryCount - 1 do
      if FRegistry[I] = AConn then
      begin
        Live := True;
        TId := AConn.FTConn.Id;
        Break;
      end;
  finally
    FLock.Release;
  end;
  if not Live then Exit; // already gone: silently dropped
  New(Env);
  Env^.Proc := AProc;
  FTransport.SubmitPost(TId, Env);
end;

function TWSServer.DropConn(AConn: TWSConnection): Boolean;
var
  TConn: TWSTransportConn;
begin
  Result := False;
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

function TWSServer.FinishHandshake(AConn: TWSConnection): Boolean;
var
  HS: TWSServerHandshake;
  Resp: RawByteString;
begin
  Result := False;
  if not ServerParseRequest(AConn.FHsBuf, FAllowDeflate, HS) then
  begin
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

  if Assigned(FOnOpen) then FOnOpen(AConn);
  Result := True;
end;

function TWSServer.IngestAndFlush(AConn: TWSConnection; P: PByte;
  ALen: NativeInt): Boolean;
begin
  Result := False;
  if not AConn.FProto.Ingest(P, ALen) then
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
        if not FinishHandshake(Conn) then Exit;
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
