unit WS.Server;

// Single-threaded epoll reactor (Linux). The shape every fast WebSocket
// server converges on — uWebSockets, tokio-websockets' bench harness,
// websocket.zig's nonblocking mode — one event loop, nonblocking sockets,
// level-triggered readiness, EPOLLOUT armed only while a connection has
// backlog.
//
// Per connection: a TWSProtocol does every byte of RFC 6455; this unit
// only moves bytes between epoll and that machine. Handshakes are
// accumulated until the blank line, parsed by WS.Handshake, answered, and
// the socket flips from "handshaking" to "open".
//
// Reads land in ONE shared 256 KB buffer — Ingest consumes it fully
// (copying only partial trailing frames into the connection's carry), so
// by the next readiness event the buffer is free again. Zero steady-state
// allocation on the hot echo path.

{$I Shared.inc}

interface

{$ifdef LINUX}

uses
  BaseUnix,
  SysUtils,
  Unix,

  Linux,
  Sockets,
  WS.Handshake,
  WS.Protocol;

type
  TWSServer = class;

  TWSConnState = (wcsHandshake, wcsOpen, wcsClosing);

  TWSConnection = class
  private
    FServer: TWSServer;
    FFd: Integer;
    FState: TWSConnState;
    FProto: TWSProtocol;
    FHsBuf: RawByteString;     // handshake accumulator
    FWantWrite: Boolean;
    procedure ProtoMessage(AText: Boolean; P: PByte; ALen: NativeInt);
  public
    UserData: Pointer;
    destructor Destroy; override;
    procedure SendText(P: PByte; ALen: NativeInt);
    procedure SendBinary(P: PByte; ALen: NativeInt);
    procedure Close(ACode: Word = 1000; const AReason: string = '');
    property Proto: TWSProtocol read FProto;
    property Fd: Integer read FFd;
  end;

  TWSServerMessage = procedure(AConn: TWSConnection; AText: Boolean;
    P: PByte; Len: NativeInt) of object;
  TWSServerNotify = procedure(AConn: TWSConnection) of object;

  TWSServer = class
  private
    FListenFd, FEpFd: Integer;
    FPort: Word;
    FAllowDeflate: Boolean;
    FMaxMessage: NativeInt;
    FConns: array of TWSConnection;   // fd-indexed
    FRecv: TBytes;                    // shared read buffer
    FRunning: Boolean;
    FOnMessage: TWSServerMessage;
    FOnOpen, FOnClose: TWSServerNotify;

    procedure EpollMod(AFd: Integer; AEvents: Cardinal);
    procedure Track(AConn: TWSConnection);
    procedure Drop(AConn: TWSConnection);
    procedure AcceptPending;
    procedure HandleReadable(AConn: TWSConnection);
    procedure HandleWritable(AConn: TWSConnection);
    procedure FlushConn(AConn: TWSConnection);
    procedure FinishHandshake(AConn: TWSConnection);
  public
    constructor Create(APort: Word; AAllowDeflate: Boolean = True;
      AMaxMessage: NativeInt = 16 * 1024 * 1024);
    destructor Destroy; override;

    // Blocks. ATimeoutMs >= 0 returns after one epoll_wait round (test use);
    // -1 loops until Stop.
    procedure Run(ATimeoutMs: Integer = -1);
    procedure Stop;

    property Port: Word read FPort;
    property OnMessage: TWSServerMessage read FOnMessage write FOnMessage;
    property OnOpen: TWSServerNotify read FOnOpen write FOnOpen;
    property OnClientClose: TWSServerNotify read FOnClose write FOnClose;
  end;

{$endif}

implementation

{$ifdef LINUX}

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

{ TWSConnection }

destructor TWSConnection.Destroy;
begin
  FProto.Free;
  inherited;
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
var
  SA: TInetSockAddr;
  One: Integer;
  Ev: TEPoll_Event;
  Len: TSockLen;
begin
  inherited Create;
  FAllowDeflate := AAllowDeflate;
  FMaxMessage := AMaxMessage;
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
  FPort := ntohs(SA.sin_port);

  SetNonBlocking(FListenFd);

  FEpFd := epoll_create(1024);
  if FEpFd < 0 then raise Exception.Create('epoll_create failed');
  Ev.events := EPOLLIN;
  Ev.data.fd := FListenFd;
  epoll_ctl(FEpFd, EPOLL_CTL_ADD, FListenFd, @Ev);
end;

destructor TWSServer.Destroy;
var
  I: Integer;
begin
  for I := 0 to High(FConns) do
    if FConns[I] <> nil then
    begin
      FileClose(FConns[I].FFd);
      FConns[I].Free;
    end;
  if FEpFd >= 0 then FileClose(FEpFd);
  if FListenFd >= 0 then CloseSocket(FListenFd);
  inherited;
end;

procedure TWSServer.EpollMod(AFd: Integer; AEvents: Cardinal);
var
  Ev: TEPoll_Event;
begin
  Ev.events := AEvents;
  Ev.data.fd := AFd;
  epoll_ctl(FEpFd, EPOLL_CTL_MOD, AFd, @Ev);
end;

procedure TWSServer.Track(AConn: TWSConnection);
begin
  if AConn.FFd >= Length(FConns) then
    SetLength(FConns, AConn.FFd + 64);
  FConns[AConn.FFd] := AConn;
end;

procedure TWSServer.Drop(AConn: TWSConnection);
begin
  epoll_ctl(FEpFd, EPOLL_CTL_DEL, AConn.FFd, nil);
  CloseSocket(AConn.FFd);
  FConns[AConn.FFd] := nil;
  if (AConn.FState <> wcsHandshake) and Assigned(FOnClose) then
    FOnClose(AConn);
  AConn.Free;
end;

procedure TWSServer.AcceptPending;
var
  Fd: Integer;
  Conn: TWSConnection;
  Ev: TEPoll_Event;
begin
  repeat
    Fd := fpAccept(FListenFd, nil, nil);
    if Fd < 0 then Exit; // EAGAIN: drained
    SetNonBlocking(Fd);
    SetNoDelay(Fd);
    Conn := TWSConnection.Create;
    Conn.FServer := Self;
    Conn.FFd := Fd;
    Conn.FState := wcsHandshake;
    Track(Conn);
    Ev.events := EPOLLIN;
    Ev.data.fd := Fd;
    epoll_ctl(FEpFd, EPOLL_CTL_ADD, Fd, @Ev);
  until False;
end;

procedure TWSServer.FinishHandshake(AConn: TWSConnection);
var
  HS: TWSServerHandshake;
  Resp: RawByteString;
begin
  if not ServerParseRequest(AConn.FHsBuf, FAllowDeflate, HS) then
  begin
    Resp := ServerBuildReject(400, HS.Failure);
    fpSend(AConn.FFd, @Resp[1], Length(Resp), 0);
    Drop(AConn);
    Exit;
  end;

  AConn.FProto := TWSProtocol.Create(wsrServer, HS.Deflate, FMaxMessage);
  AConn.FProto.OnMessage := AConn.ProtoMessage;

  // Hand the 101 to the protocol's out queue so a partial send shares the
  // one backpressure path (EPOLLOUT arming, ordered before any frame the
  // open handler queues).
  Resp := ServerBuildResponse(HS);
  AConn.FProto.QueueRaw(@Resp[1], Length(Resp));
  AConn.FState := wcsOpen;
  AConn.FHsBuf := '';
  FlushConn(AConn);
  if FConns[AConn.FFd] <> AConn then Exit; // send error dropped it

  if Assigned(FOnOpen) then FOnOpen(AConn);
end;

procedure TWSServer.HandleReadable(AConn: TWSConnection);
var
  Got: Integer;
  HdrEnd: Integer;
  Off: Integer;
begin
  repeat
    Got := fpRecv(AConn.FFd, @FRecv[0], Length(FRecv), 0);
    if Got = 0 then
    begin
      Drop(AConn);
      Exit;
    end;
    if Got < 0 then Exit; // EAGAIN

    case AConn.FState of
      wcsHandshake:
        begin
          Off := Length(AConn.FHsBuf);
          SetLength(AConn.FHsBuf, Off + Got);
          Move(FRecv[0], AConn.FHsBuf[Off + 1], Got);
          if Length(AConn.FHsBuf) > 16 * 1024 then
          begin
            Drop(AConn);
            Exit;
          end;
          HdrEnd := HandshakeFindEnd(AConn.FHsBuf);
          if HdrEnd > 0 then
          begin
            // Frames pipelined behind the request get replayed post-101.
            FinishHandshake(AConn);
            if FConns[AConn.FFd] <> AConn then Exit; // dropped
            if AConn.FState = wcsOpen then
              if HdrEnd < Off + Got then
                if not AConn.FProto.Ingest(@FRecv[HdrEnd - Off], Off + Got - HdrEnd) then
                begin
                  FlushConn(AConn);
                  Exit;
                end;
          end;
        end;
      wcsOpen, wcsClosing:
        begin
          if not AConn.FProto.Ingest(@FRecv[0], Got) then
          begin
            FlushConn(AConn); // get the close frame out, then die
            if FConns[AConn.FFd] = AConn then Drop(AConn);
            Exit;
          end;
          FlushConn(AConn);
          if FConns[AConn.FFd] <> AConn then Exit;
          if AConn.FProto.CloseDone and (AConn.FProto.OutPending = 0) then
          begin
            Drop(AConn);
            Exit;
          end;
        end;
    end;
  until False;
end;

procedure TWSServer.FlushConn(AConn: TWSConnection);
var
  N, W: NativeInt;
begin
  while AConn.FProto.OutPending > 0 do
  begin
    N := AConn.FProto.OutPending;
    W := fpSend(AConn.FFd, AConn.FProto.OutPtr, N, MSG_NOSIGNAL);
    if W < 0 then
    begin
      if fpgeterrno = ESysEAGAIN then
      begin
        if not AConn.FWantWrite then
        begin
          AConn.FWantWrite := True;
          EpollMod(AConn.FFd, EPOLLIN or EPOLLOUT);
        end;
        Exit;
      end;
      Drop(AConn);
      Exit;
    end;
    AConn.FProto.OutConsume(W);
  end;
  if AConn.FWantWrite then
  begin
    AConn.FWantWrite := False;
    EpollMod(AConn.FFd, EPOLLIN);
  end;
end;

procedure TWSServer.HandleWritable(AConn: TWSConnection);
begin
  FlushConn(AConn);
  if FConns[AConn.FFd] <> AConn then Exit;
  if AConn.FProto <> nil then
    if AConn.FProto.CloseDone and (AConn.FProto.OutPending = 0) then
      Drop(AConn);
end;

procedure TWSServer.Run(ATimeoutMs: Integer);
var
  Evs: array[0..255] of TEPoll_Event;
  N, I, Fd: Integer;
  Conn: TWSConnection;
begin
  FRunning := True;
  repeat
    N := epoll_wait(FEpFd, @Evs[0], Length(Evs), ATimeoutMs);
    for I := 0 to N - 1 do
    begin
      Fd := Evs[I].data.fd;
      if Fd = FListenFd then
      begin
        AcceptPending;
        Continue;
      end;
      if (Fd >= Length(FConns)) or (FConns[Fd] = nil) then Continue;
      Conn := FConns[Fd];
      if (Evs[I].events and (EPOLLERR or EPOLLHUP)) <> 0 then
      begin
        Drop(Conn);
        Continue;
      end;
      if (Evs[I].events and EPOLLOUT) <> 0 then
      begin
        HandleWritable(Conn);
        if FConns[Fd] <> Conn then Continue;
      end;
      if (Evs[I].events and EPOLLIN) <> 0 then
        HandleReadable(Conn);
    end;
  until (not FRunning) or (ATimeoutMs >= 0);
end;

procedure TWSServer.Stop;
begin
  FRunning := False;
end;

{$endif}

end.
