unit WS.Server;

// Platform-neutral WebSocket server session layer. Per connection: a
// TWSProtocol does every byte of RFC 6455; this unit only moves bytes
// between the platform transport (WS.Transport, selected per platform
// below) and that machine. Handshakes are accumulated until the blank
// line, parsed by WS.Handshake, answered, and the connection flips from
// "handshaking" to "open".
//
// Concurrency (ADR-0003): callbacks fire on the transport's execution
// context — the Run thread on Linux (epoll), per-connection serial
// dispatch queues on macOS (Network.framework). Per-connection order is
// guaranteed everywhere; handlers for DIFFERENT connections may run
// concurrently on macOS, so cross-connection state in user handlers
// needs the user's own synchronization. The hot path here is confined
// to one connection and stays lock-free; the only lock guards the
// connection registry on accept/close (cold path).

{$I Shared.inc}

interface

{$if defined(LINUX) or defined(DARWIN)}

uses
  syncobjs,
  SysUtils,

  WS.Handshake,
  WS.Protocol,
  WS.Transport;

type
  TWSServer = class;

  TWSConnState = (wcsHandshake, wcsOpen, wcsClosing);

  TWSConnection = class
  private
    FServer: TWSServer;
    FTConn: TWSTransportConn;
    FState: TWSConnState;
    FProto: TWSProtocol;
    FHsBuf: RawByteString;     // handshake accumulator
    procedure ProtoMessage(AText: Boolean; P: PByte; ALen: NativeInt);
    function GetId: NativeUInt;
  public
    UserData: Pointer;
    destructor Destroy; override;
    procedure SendText(P: PByte; ALen: NativeInt);
    procedure SendBinary(P: PByte; ALen: NativeInt);
    procedure Close(ACode: Word = 1000; const AReason: string = '');
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
    FConns: array of TWSConnection;
    FConnCount: Integer;
    FLock: TCriticalSection;
    FOnMessage: TWSServerMessage;
    FOnOpen, FOnClose: TWSServerNotify;

    procedure RegistryAdd(AConn: TWSConnection);
    procedure RegistryRemove(AConn: TWSConnection);
    // Caller-initiated teardown; returns False so drop sites can chain
    // "Exit(DropConn(...))". The connection is freed on return.
    function DropConn(AConn: TWSConnection): Boolean;
    // Hands pending protocol output to the transport. False = the
    // connection died and was dropped.
    function FlushConn(AConn: TWSConnection): Boolean;
    function FinishHandshake(AConn: TWSConnection): Boolean;
    function IngestAndFlush(AConn: TWSConnection; P: PByte;
      ALen: NativeInt): Boolean;

    procedure HandleAccept(ATConn: TWSTransportConn);
    procedure HandleData(ATConn: TWSTransportConn; P: PByte; ALen: NativeInt);
    procedure HandleSendReady(ATConn: TWSTransportConn);
    procedure HandleClosed(ATConn: TWSTransportConn);
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

{$if defined(LINUX) or defined(DARWIN)}

uses
  {$ifdef LINUX}
  WS.Transport.Epoll;
  {$endif}
  {$ifdef DARWIN}
  WS.Transport.NetworkFramework;
  {$endif}

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

procedure TWSConnection.SendText(P: PByte; ALen: NativeInt);
begin
  if FState = wcsOpen then
  begin
    FProto.SendText(P, ALen);
    FServer.FlushConn(Self);
  end;
end;

procedure TWSConnection.SendBinary(P: PByte; ALen: NativeInt);
begin
  if FState = wcsOpen then
  begin
    FProto.SendBinary(P, ALen);
    FServer.FlushConn(Self);
  end;
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
  FTransport.OnAccept := HandleAccept;
  FTransport.OnData := HandleData;
  FTransport.OnSendReady := HandleSendReady;
  FTransport.OnClosed := HandleClosed;
end;

destructor TWSServer.Destroy;
var
  I: Integer;
begin
  // Stop has been called and Run has returned by contract; teardown is
  // single-threaded from here.
  for I := 0 to FConnCount - 1 do
  begin
    FConns[I].FTConn.UserData := nil;
    FConns[I].FTConn.SubmitClose;
    FConns[I].Free;
  end;
  FTransport.Free;
  FLock.Free;
  inherited;
end;

procedure TWSServer.RegistryAdd(AConn: TWSConnection);
begin
  FLock.Acquire;
  try
    if FConnCount = Length(FConns) then
      SetLength(FConns, FConnCount + 64);
    FConns[FConnCount] := AConn;
    Inc(FConnCount);
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
    for I := 0 to FConnCount - 1 do
      if FConns[I] = AConn then
      begin
        FConns[I] := FConns[FConnCount - 1];
        FConns[FConnCount - 1] := nil;
        Dec(FConnCount);
        Break;
      end;
  finally
    FLock.Release;
  end;
end;

function TWSServer.DropConn(AConn: TWSConnection): Boolean;
begin
  Result := False;
  RegistryRemove(AConn);
  if (AConn.FState <> wcsHandshake) and Assigned(FOnClose) then
    FOnClose(AConn);
  AConn.FTConn.UserData := nil;
  AConn.FTConn.SubmitClose;
  AConn.Free;
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
    // Get the close frame out, then die.
    if FlushConn(AConn) then DropConn(AConn);
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
        if Length(Conn.FHsBuf) > 16 * 1024 then
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
    if Conn.FProto.CloseDone and (Conn.FProto.OutPending = 0) then
      DropConn(Conn);
end;

procedure TWSServer.HandleClosed(ATConn: TWSTransportConn);
var
  Conn: TWSConnection;
begin
  Conn := TWSConnection(ATConn.UserData);
  if Conn = nil then Exit;
  RegistryRemove(Conn);
  if (Conn.FState <> wcsHandshake) and Assigned(FOnClose) then
    FOnClose(Conn);
  Conn.Free;
  // The transport frees ATConn after this callback returns.
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
