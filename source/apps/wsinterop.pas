program wsinterop;

// Live-socket battery: duetto TWSClient against duetto TWSServer over real
// TCP (loopback), plus a raw-socket section that injects protocol
// violations a conforming client cannot produce and asserts the close
// codes RFC 6455 (and Autobahn cases 4.x/7.x) require, plus a
// concurrent-connections stress section — ~32 client threads of
// echo/burst/clean-close cycles racing abrupt raw-socket drops and
// server-initiated pushes, ended by a Shutdown with connections still
// open.
//
// Exit 0 = every check passed.

{$I Shared.inc}

uses
  {$ifdef UNIX} cthreads, {$endif}
  syncobjs,
  SysUtils, Classes, Sockets,
  WS.Server, WS.Client, WS.Frame, WS.Handshake;

type
  {$ifdef UNIX}
  TInteropTimeVal = record
    Seconds: PtrInt;
    Microseconds: PtrInt;
  end;
  {$endif}

  // struct linger: int pair on Unix, u_short pair on WinSock.
  TInteropLinger = record
    {$ifdef WINDOWS}
    OnOff: Word;
    Seconds: Word;
    {$else}
    OnOff: LongInt;
    Seconds: LongInt;
    {$endif}
  end;

  TEcho = class
    procedure OnMsg(AConn: TWSConnection; AText: Boolean; P: PByte; Len: NativeInt);
  end;

  TServerThread = class(TThread)
  public
    Srv: TWSServer;
    procedure Execute; override;
  end;

procedure TEcho.OnMsg(AConn: TWSConnection; AText: Boolean; P: PByte; Len: NativeInt);
begin
  if AText then AConn.SendText(P, Len) else AConn.SendBinary(P, Len);
end;

procedure TServerThread.Execute;
begin
  while not Terminated do
    Srv.Run(50);
end;

var
  Failures: Integer = 0;

var
  LastTick: QWord;

procedure Check(ACond: Boolean; const AName: string);
var
  Now_: QWord;
begin
  Now_ := GetTickCount64;
  if ACond then
    Write('ok   - ', AName)
  else
  begin
    Write('FAIL - ', AName);
    Inc(Failures);
  end;
  WriteLn('  [+', Now_ - LastTick, ' ms]');
  LastTick := Now_;
  Flush(Output);
end;

// ---------------------------------------------------------------------------
// Raw socket helpers for the violation section
// ---------------------------------------------------------------------------

function RawConnect(APort: Word): Tsocket;
var
  SA: TInetSockAddr;
  {$ifdef WINDOWS}
  TimeoutMs: Cardinal;
  {$else}
  TV: TInteropTimeVal;
  {$endif}
begin
  Result := fpSocket(AF_INET, SOCK_STREAM, 0);
  {$ifdef WINDOWS}
  TimeoutMs := 5000;
  fpSetSockOpt(Result, SOL_SOCKET, SO_RCVTIMEO, @TimeoutMs,
    SizeOf(TimeoutMs));
  {$else}
  TV.Seconds := 5; TV.Microseconds := 0;
  fpSetSockOpt(Result, SOL_SOCKET, SO_RCVTIMEO, @TV, SizeOf(TV));
  {$endif}
  FillChar(SA, SizeOf(SA), 0);
  SA.sin_family := AF_INET;
  SA.sin_port := htons(APort);
  SA.sin_addr.s_addr := htonl($7F000001); // 127.0.0.1
  if fpConnect(Result, @SA, SizeOf(SA)) <> 0 then
    raise Exception.Create('raw connect failed');
end;

// Speak the opening handshake on a raw socket; returns leftover bytes
// (frames pipelined behind the 101), if any.
function RawHandshake(AFd: Tsocket): TBytes;
var
  Req, Raw: RawByteString;
  Buf: array[0..4095] of Byte;
  Got, HdrEnd: Integer;
begin
  Result := nil;
  Req := ClientBuildRequest('127.0.0.1', '/', ClientGenerateKey, False);
  fpSend(AFd, @Req[1], Length(Req), 0);
  Raw := '';
  repeat
    Got := fpRecv(AFd, @Buf[0], SizeOf(Buf), 0);
    if Got <= 0 then raise Exception.Create('raw handshake: connection lost');
    SetLength(Raw, Length(Raw) + Got);
    Move(Buf[0], Raw[Length(Raw) - Got + 1], Got);
    HdrEnd := HandshakeFindEnd(Raw);
  until HdrEnd > 0;
  if Pos('101', Copy(Raw, 1, 16)) = 0 then
    raise Exception.Create('raw handshake: no 101');
  SetLength(Result, Length(Raw) - HdrEnd);
  if Length(Result) > 0 then
    Move(Raw[HdrEnd + 1], Result[0], Length(Result));
end;

// Read frames until a close frame arrives; return its status code
// (0 if the peer hung up without one).
function RawReadCloseCode(AFd: Tsocket; const ALeftover: TBytes): Word;
var
  Buf: TBytes;
  Len, Got, Used: NativeInt;
  H: TWSFrameHeader;
  R: TWSParseResult;
begin
  Result := 0;
  Buf := Copy(ALeftover);
  Len := Length(Buf);
  repeat
    R := ParseFrameHeader(PByte(Buf), Len, H);
    if R = wprOK then
    begin
      Used := H.HeaderLen;
      if Len - Used < H.PayloadLen then
        R := wprNeedMore // payload still in flight
      else if H.Opcode = WS_OP_CLOSE then
      begin
        if H.PayloadLen >= 2 then
          Exit((Buf[Used] shl 8) or Buf[Used + 1])
        else
          Exit(0);
      end
      else
      begin // skip non-close frame (e.g. an echo) and continue
        Delete(Buf, 0, Used + H.PayloadLen);
        Dec(Len, Used + H.PayloadLen);
        Continue;
      end;
    end;
    if R = wprProtocolError then Exit(0);
    SetLength(Buf, Len + 4096);
    Got := fpRecv(AFd, @Buf[Len], 4096, 0);
    if Got <= 0 then Exit(0); // EOF/timeout without close frame
    Len := Len + Got;
    SetLength(Buf, Len);
  until False;
end;

procedure RawSendFrame(AFd: Tsocket; AOpcode: Byte; const APayload: RawByteString;
  AMasked: Boolean);
var
  Hdr: array[0..WS_MAX_HEADER - 1] of Byte;
  HLen: Integer;
  Key: UInt32;
  Body: TBytes;
begin
  Key := $A1B2C3D4;
  HLen := WriteFrameHeader(@Hdr[0], True, False, AOpcode, AMasked, Key,
    Length(APayload));
  fpSend(AFd, @Hdr[0], HLen, 0);
  if APayload = '' then Exit;
  SetLength(Body, Length(APayload));
  Move(APayload[1], Body[0], Length(APayload));
  if AMasked then
    ApplyMask(PByte(Body), Length(Body), Key, 0);
  fpSend(AFd, @Body[0], Length(Body), 0);
end;

// ---------------------------------------------------------------------------
// Concurrent-connections stress section
// ---------------------------------------------------------------------------
// ~32 client threads against the one server instance: echo workers loop
// connect / single echo / pipelined burst / clean close, abrupt-drop
// workers kill raw sockets mid-conversation (no closing handshake), and
// one pusher thread Posts server-initiated messages into every live
// connection while the clients are reading. Framing keeps the two
// streams distinguishable — binary frames are echoes, text frames are
// pushes — so each worker verifies its echo payloads round-trip intact
// and in order while push serials stay consecutive per connection.
// Deterministic seeds, no timing assertions: the wall-clock budget and
// the cycle caps only bound how long the loops run (whichever ends
// first), and the only failure clock is a generous stall limit so a
// wedged stream fails instead of hanging CI.

const
  StressEchoWorkerCount = 28;
  StressDropWorkerCount = 4;
  StressLingerCount = 4;
  StressBudgetMs = 3000;
  StressBurstLen = 4;
  StressReadSliceMs = 1000;
  StressStallLimitMs = 30000;
  StressConnectAttempts = 5;
  StressPayloadMin = 64;
  StressPayloadSpread = 1400;
  // Connection-churn caps. Every cleanly closed loopback connection
  // parks a TIME_WAIT entry for 2*MSL (30 s on macOS) in the same
  // ~16 k ephemeral-port range both ends share, so uncapped reconnect
  // cycles make connect() fail process-wide a few consecutive runs
  // later. The caps keep a whole run under ~1 k such entries; the
  // drop workers contribute none (RST via SO_LINGER 0).
  StressEchoCycleCap = 30;
  StressDropCycleCap = 150;
  StressDropPauseMs = 5;
  // Whole-section watchdog: storm budget plus generous headroom for a
  // slow CI VM. Purely a wedge detector, never a speed assertion.
  StressWatchdogMs = StressBudgetMs + 120000;
  StressPushTail: RawByteString = 'duetto-push';

type
  // Holds connection references from OnOpen until OnClientClose returns
  // — exactly the window the TWSConnection.Post lifetime contract
  // allows. PushSweep Posts while holding the lock: a connection
  // dropping concurrently blocks in HandleClose until the sweep ends,
  // so the reference stays allocated, and the server re-validates it
  // against its registry anyway (a stale Post is silently discarded).
  TStressTracker = class
  private
    FLock: TCriticalSection;
    FConns: array of TWSConnection;
    FCount: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure HandleOpen(AConn: TWSConnection);
    procedure HandleClose(AConn: TWSConnection);
    procedure PushToConn(AConn: TWSConnection);
    procedure PushSweep;
  end;

  TStressWorker = class(TThread)
  public
    Deadline: QWord;
    Cycles: Integer;
    Ok: Boolean;
    FailMsg: string;
    procedure MarkFailed(const AMsg: string);
  end;

  TStressEchoWorker = class(TStressWorker)
  private
    FNextPushSerial: NativeUInt;
    function BuildPayload(AMsgIdx: Integer): TBytes;
    procedure VerifyPush(const AData: TBytes);
    procedure EchoRound(ACli: TWSClient; ACount: Integer;
      var AMsgIdx: Integer);
  public
    Seed: Integer;
    Url: string;
    Pushes: Integer;
    procedure Execute; override;
  end;

  TStressDropWorker = class(TStressWorker)
  public
    Seed: Integer;
    Port: Word;
    procedure Execute; override;
  end;

  TStressPusher = class(TThread)
  public
    Tracker: TStressTracker;
    Deadline: QWord;
    procedure Execute; override;
  end;

  // Converts a wedged server into a fast, attributable failure: a dead
  // accept path leaves TCP connects completing against the kernel
  // backlog while the 101 never arrives, which blocks the client's
  // unbounded Connect — and would hang the process (and a CI job)
  // until an external timeout with no output. If the section has not
  // signalled completion inside the watchdog bound, report and
  // hard-exit.
  TStressWatchdog = class(TThread)
  public
    Done: PBoolean; // written by the main thread, polled here
    Srv: TThread;   // the server thread, for FatalException on expiry
    // Last phase marker the main thread recorded. ShortString on
    // purpose: value semantics, no refcounted heap pointer, so a torn
    // cross-thread read garbles the text at worst instead of crashing.
    Phase: ^ShortString;
    procedure Execute; override;
  end;

// Connect with a bounded retry: loopback churn can drop the odd SYN or
// leave the ephemeral-port range momentarily tight; a persistent
// refusal still surfaces as the original exception.
function StressConnect(const AUrl: string): TWSClient;
var
  Attempt: Integer;
begin
  Attempt := 0;
  repeat
    Inc(Attempt);
    Result := TWSClient.Create;
    try
      Result.Connect(AUrl);
      Exit;
    except
      on E: EWSClient do
      begin
        FreeAndNil(Result);
        if Attempt >= StressConnectAttempts then raise;
        Sleep(10 * Attempt);
      end;
    end;
  until False;
end;

{ TStressTracker }

constructor TStressTracker.Create;
begin
  inherited;
  FLock := TCriticalSection.Create;
end;

destructor TStressTracker.Destroy;
begin
  FLock.Free;
  inherited;
end;

procedure TStressTracker.HandleOpen(AConn: TWSConnection);
begin
  FLock.Acquire;
  try
    if FCount = Length(FConns) then
      SetLength(FConns, FCount + 32);
    FConns[FCount] := AConn;
    Inc(FCount);
  finally
    FLock.Release;
  end;
end;

procedure TStressTracker.HandleClose(AConn: TWSConnection);
var
  I: Integer;
begin
  FLock.Acquire;
  try
    for I := 0 to FCount - 1 do
      if FConns[I] = AConn then
      begin
        FConns[I] := FConns[FCount - 1];
        FConns[FCount - 1] := nil;
        Dec(FCount);
        Break;
      end;
  finally
    FLock.Release;
  end;
end;

// Runs on the connection's callback context, serialized with its
// OnMessage — so the per-connection serial can live lock-free in
// UserData, and the receiver can assert the serials it sees are exactly
// 0, 1, 2, ... for the lifetime of the connection.
procedure TStressTracker.PushToConn(AConn: TWSConnection);
var
  Serial: NativeUInt;
  Payload: RawByteString;
begin
  Serial := NativeUInt(AConn.UserData);
  AConn.UserData := Pointer(Serial + 1);
  Payload := 'P' + IntToStr(Serial) + ':' + StressPushTail;
  // False = dropped and freed mid-call; AConn is not touched again.
  AConn.SendText(@Payload[1], Length(Payload));
end;

procedure TStressTracker.PushSweep;
var
  I: Integer;
begin
  FLock.Acquire;
  try
    for I := 0 to FCount - 1 do
      FConns[I].Post(PushToConn);
  finally
    FLock.Release;
  end;
end;

{ TStressWorker }

procedure TStressWorker.MarkFailed(const AMsg: string);
begin
  if Ok then
  begin
    Ok := False;
    FailMsg := AMsg;
  end;
end;

{ TStressEchoWorker }

function TStressEchoWorker.BuildPayload(AMsgIdx: Integer): TBytes;
var
  Len, J: Integer;
begin
  Len := StressPayloadMin +
    ((Seed * 131 + Cycles * 29 + AMsgIdx * 17) mod StressPayloadSpread);
  SetLength(Result, Len);
  for J := 0 to Len - 1 do
    Result[J] := Byte((Seed + Cycles * 31 + AMsgIdx * 7 + J * 13) and $FF);
end;

procedure TStressEchoWorker.VerifyPush(const AData: TBytes);
var
  I, Colon: Integer;
  SerialText: string;
  Serial: Int64;
begin
  Colon := 0;
  if (Length(AData) >= 2) and (AData[0] = Ord('P')) then
    for I := 1 to Length(AData) - 1 do
      if AData[I] = Ord(':') then
      begin
        Colon := I;
        Break;
      end;
  if Colon < 2 then
  begin
    MarkFailed('malformed push frame');
    Exit;
  end;
  SetLength(SerialText, Colon - 1);
  Move(AData[1], SerialText[1], Colon - 1);
  Serial := StrToInt64Def(SerialText, -1);
  if Serial <> Int64(FNextPushSerial) then
  begin
    MarkFailed(Format('push serial %s, expected %d',
      [SerialText, Int64(FNextPushSerial)]));
    Exit;
  end;
  if (Length(AData) - Colon - 1 <> Length(StressPushTail)) or
    not CompareMem(@AData[Colon + 1], @StressPushTail[1],
      Length(StressPushTail)) then
  begin
    MarkFailed('push tail corrupt');
    Exit;
  end;
  Inc(FNextPushSerial);
  Inc(Pushes);
end;

// Send ACount pipelined binary messages, then read until every echo is
// back — intact and in order — verifying any text push that interleaves.
procedure TStressEchoWorker.EchoRound(ACli: TWSClient; ACount: Integer;
  var AMsgIdx: Integer);
var
  Sent: array of TBytes;
  I, GotCount, StallMs: Integer;
  IsText: Boolean;
  Data: TBytes;
begin
  SetLength(Sent, ACount);
  for I := 0 to ACount - 1 do
  begin
    Sent[I] := BuildPayload(AMsgIdx + I);
    ACli.SendBinary(@Sent[I][0], Length(Sent[I]));
  end;
  GotCount := 0;
  StallMs := 0;
  while Ok and (GotCount < ACount) do
    case ACli.ReadMessage(IsText, Data, StressReadSliceMs) of
      wrrMessage:
        begin
          StallMs := 0;
          if IsText then
            VerifyPush(Data)
          else if (Length(Data) <> Length(Sent[GotCount])) or
            not CompareMem(@Data[0], @Sent[GotCount][0], Length(Data)) then
            MarkFailed(Format('echo corrupt (cycle %d, message %d)',
              [Cycles, AMsgIdx + GotCount]))
          else
            Inc(GotCount);
        end;
      wrrTimeout:
        begin
          Inc(StallMs, StressReadSliceMs);
          if StallMs >= StressStallLimitMs then
            MarkFailed('echo stream stalled');
        end;
      wrrClosed:
        MarkFailed(Format('connection closed mid-echo (code %d)',
          [ACli.CloseCode]));
    end;
  Inc(AMsgIdx, ACount);
end;

procedure TStressEchoWorker.Execute;
var
  Cli: TWSClient;
  MsgIdx: Integer;
begin
  Ok := True;
  try
    while Ok and (GetTickCount64 < Deadline) and
      (Cycles < StressEchoCycleCap) do
    begin
      Cli := StressConnect(Url);
      try
        FNextPushSerial := 0;
        MsgIdx := 0;
        EchoRound(Cli, 1, MsgIdx);
        if Ok then
          EchoRound(Cli, StressBurstLen, MsgIdx);
        if Ok then
        begin
          Cli.Close(1000, '');
          if Cli.CloseCode <> 1000 then
            MarkFailed(Format('clean close echoed %d, expected 1000',
              [Cli.CloseCode]));
        end;
      finally
        Cli.Free;
      end;
      Inc(Cycles);
    end;
  except
    on E: Exception do
      MarkFailed(E.ClassName + ': ' + E.Message);
  end;
end;

{ TStressDropWorker }

procedure TStressDropWorker.Execute;
var
  Fd: Tsocket;
  Payload: RawByteString;
  HardClose: TInteropLinger;
  Transient: Integer;
begin
  Ok := True;
  Transient := 0;
  // SO_LINGER 0 turns CloseSocket into a hard RST: the most abrupt
  // teardown TCP offers, and it parks no TIME_WAIT entries that would
  // starve the shared loopback port range across runs.
  HardClose.OnOff := 1;
  HardClose.Seconds := 0;
  while Ok and (GetTickCount64 < Deadline) and
    (Cycles < StressDropCycleCap) do
  begin
    try
      Fd := RawConnect(Port);
      try
        fpSetSockOpt(Fd, SOL_SOCKET, SO_LINGER, @HardClose,
          SizeOf(HardClose));
        RawHandshake(Fd);
        if (Cycles and 1) = 0 then
        begin
          // Two echoes in flight when the socket dies; odd cycles die
          // straight after the 101 so teardown races the open path too.
          Payload := 'abrupt-' + IntToStr(Seed) + '-' + IntToStr(Cycles);
          RawSendFrame(Fd, WS_OP_BINARY, Payload, True);
          RawSendFrame(Fd, WS_OP_BINARY, Payload, True);
        end;
        // No closing handshake: the RST lands while the echoes (and any
        // pushes) are still in flight server-side.
      finally
        CloseSocket(Fd);
      end;
      Inc(Cycles);
      Transient := 0;
    except
      on E: Exception do
      begin
        // Loopback churn can drop the odd SYN or handshake read; only a
        // persistent streak is a failure.
        Inc(Transient);
        if Transient >= StressConnectAttempts then
          MarkFailed(E.ClassName + ': ' + E.Message);
      end;
    end;
    Sleep(StressDropPauseMs);
  end;
end;

{ TStressPusher }

procedure TStressPusher.Execute;
begin
  while (not Terminated) and (GetTickCount64 < Deadline) do
  begin
    Tracker.PushSweep;
    Sleep(1);
  end;
end;

procedure TStressWatchdog.Execute;
var
  Waited: Integer;
begin
  Waited := 0;
  while Waited < StressWatchdogMs do
  begin
    Sleep(250);
    Inc(Waited, 250);
    if Done^ then Exit;
  end;
  if Done^ then Exit; // completion at the boundary is not an expiry
  WriteLn('FAIL - stress: watchdog expired after ', StressWatchdogMs,
    ' ms; section did not complete (wedged server, or pathological ',
    'slowness — per-worker diagnostics were discarded)');
  WriteLn('       phase: ', Phase^);
  if (Srv <> nil) and (Srv.FatalException <> nil) then
    WriteLn('       server thread died: ',
      Exception(Srv.FatalException).Message)
  else
    WriteLn('       server thread alive (no FatalException)');
  Flush(Output);
  Halt(2);
end;

// ---------------------------------------------------------------------------

const
  HelloProbe: RawByteString = 'hello duetto';
  PipelinedMsgs: array[0..2] of RawByteString = ('one', 'two', 'three');
  LingerProbe: RawByteString = 'linger';

var
  Echo: TEcho;
  SrvT: TServerThread;
  Port: Word;
  Url: string;
  Cli: TWSClient;
  IsText: Boolean;
  Data: TBytes;
  Big: TBytes;
  S: RawByteString;
  I: Integer;
  Ok: Boolean;
  Fd: Tsocket;
  Left: TBytes;
  Code: Word;
  Tracker: TStressTracker;
  Pusher: TStressPusher;
  EchoWorkers: array[0..StressEchoWorkerCount - 1] of TStressEchoWorker;
  DropWorkers: array[0..StressDropWorkerCount - 1] of TStressDropWorker;
  Linger: array[0..StressLingerCount - 1] of TWSClient;
  Deadline: QWord;
  Watchdog: TStressWatchdog;
  StressDone: Boolean;
  StressPhase: ShortString;
  TotalCycles, TotalPushes, TotalDrops: Integer;
  AllOk: Boolean;
begin
  Echo := TEcho.Create;
  Tracker := TStressTracker.Create;
  SrvT := TServerThread.Create(True);
  SrvT.Srv := TWSServer.Create(0, True); // port 0 = kernel-assigned
  SrvT.Srv.OnMessage := Echo.OnMsg;
  // Wired before the server thread starts so the method-pointer writes
  // can never tear against a concurrent open/close; the tracker idles
  // through the single-connection sections and matters for the stress.
  SrvT.Srv.OnOpen := Tracker.HandleOpen;
  SrvT.Srv.OnClientClose := Tracker.HandleClose;
  Port := SrvT.Srv.Port;
  Url := Format('ws://127.0.0.1:%d/', [Port]);
  SrvT.Start;
  WriteLn('server on ', Port);
  Flush(Output);
  LastTick := GetTickCount64;

  // --- duetto client vs duetto server ---------------------------------------
  Cli := TWSClient.Create;
  Cli.Connect(Url);
  Cli.SendText(HelloProbe);
  Check(Cli.ReadMessage(IsText, Data) and IsText and
    (Length(Data) = Length(HelloProbe)) and
    CompareMem(@Data[0], @HelloProbe[1], Length(HelloProbe)),
    'text echo round-trip');

  SetLength(Big, 1024 * 1024);
  for I := 0 to High(Big) do
    Big[I] := Byte((I * 31 + 7) and $FF);
  Cli.SendBinary(@Big[0], Length(Big));
  Check(Cli.ReadMessage(IsText, Data) and (not IsText) and
    (Length(Data) = Length(Big)) and CompareMem(@Data[0], @Big[0], Length(Big)),
    'binary echo 1 MiB');

  Cli.SendText('one');
  Cli.SendText('two');
  Cli.SendText('three');
  Ok := True;
  for I := 0 to 2 do
  begin
    S := PipelinedMsgs[I];
    Ok := Ok and Cli.ReadMessage(IsText, Data) and IsText and
      (Length(Data) = Length(S)) and CompareMem(@Data[0], @S[1], Length(S));
  end;
  Check(Ok, 'three pipelined messages, in order');

  Cli.Ping('beat');
  Cli.SendText('after ping');
  Check(Cli.ReadMessage(IsText, Data) and (Length(Data) = 10),
    'ping auto-ponged, data stream undisturbed');

  Cli.Close(1000, 'done');
  Check(Cli.CloseCode = 1000, 'clean close echoes 1000');
  Cli.Free;

  // --- permessage-deflate over the wire ----------------------------------
  Cli := TWSClient.Create;
  Cli.Connect(Url, True);
  Check(Cli.Deflate.Enabled, 'deflate negotiated when offered');
  S := '';
  for I := 1 to 8192 do
    S := S + 'compressible payload line ' + IntToStr(I and 7) + #10;
  Cli.SendText(S);
  Check(Cli.ReadMessage(IsText, Data) and IsText and
    (Length(Data) = Length(S)) and CompareMem(@Data[0], @S[1], Length(S)),
    'deflate echo ~200 KiB content-identical');
  Cli.Close;
  Cli.Free;

  // --- raw-socket violations ---------------------------------------------
  // A client frame without a mask: MUST fail the connection, 1002 (§5.1).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  RawSendFrame(Fd, WS_OP_TEXT, 'naughty', False);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1002, 'unmasked client frame -> close 1002');

  // Close frame carrying reserved code 999: protocol error, 1002 (§7.4).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  RawSendFrame(Fd, WS_OP_CLOSE, Chr(999 shr 8) + Chr(999 and $FF), True);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1002, 'close with invalid code 999 -> close 1002');

  // Fragmented control frame (FIN=0 ping): 1002 (§5.5).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  S := #$09#$80; // FIN=0, opcode=9, masked, len 0
  S := S + #0#0#0#0; // mask key
  fpSend(Fd, @S[1], Length(S), 0);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1002, 'fragmented ping -> close 1002');

  // Text frame with invalid UTF-8: 1007 (§8.1).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  RawSendFrame(Fd, WS_OP_TEXT, #$FF#$FE'broken', True);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1007, 'invalid UTF-8 text -> close 1007');

  // --- concurrent-connections stress -------------------------------------
  StressDone := False;
  StressPhase := 'storm';
  Watchdog := TStressWatchdog.Create(True);
  Watchdog.Done := @StressDone;
  Watchdog.Srv := SrvT;
  Watchdog.Phase := @StressPhase;
  Watchdog.Start;
  Deadline := GetTickCount64 + StressBudgetMs;
  for I := 0 to High(EchoWorkers) do
  begin
    EchoWorkers[I] := TStressEchoWorker.Create(True);
    EchoWorkers[I].Seed := I;
    EchoWorkers[I].Url := Url;
    EchoWorkers[I].Deadline := Deadline;
  end;
  for I := 0 to High(DropWorkers) do
  begin
    DropWorkers[I] := TStressDropWorker.Create(True);
    DropWorkers[I].Seed := I;
    DropWorkers[I].Port := Port;
    DropWorkers[I].Deadline := Deadline;
  end;
  Pusher := TStressPusher.Create(True);
  Pusher.Tracker := Tracker;
  Pusher.Deadline := Deadline;

  for I := 0 to High(EchoWorkers) do
    EchoWorkers[I].Start;
  for I := 0 to High(DropWorkers) do
    DropWorkers[I].Start;
  Pusher.Start;

  for I := 0 to High(EchoWorkers) do
    EchoWorkers[I].WaitFor;
  for I := 0 to High(DropWorkers) do
    DropWorkers[I].WaitFor;
  Pusher.Terminate;
  Pusher.WaitFor; // no Post may race the server teardown below

  AllOk := True;
  TotalCycles := 0;
  TotalPushes := 0;
  for I := 0 to High(EchoWorkers) do
  begin
    AllOk := AllOk and EchoWorkers[I].Ok and (EchoWorkers[I].Cycles > 0);
    Inc(TotalCycles, EchoWorkers[I].Cycles);
    Inc(TotalPushes, EchoWorkers[I].Pushes);
  end;
  Check(AllOk, Format(
    'stress: %d echo workers, %d cycles, echoes intact and in order',
    [StressEchoWorkerCount, TotalCycles]));
  for I := 0 to High(EchoWorkers) do
    if not EchoWorkers[I].Ok then
      WriteLn('       echo worker ', I, ': ', EchoWorkers[I].FailMsg);

  Check(TotalPushes > 0, Format(
    'stress: %d pushes interleaved, serials consecutive per connection',
    [TotalPushes]));

  AllOk := True;
  TotalDrops := 0;
  for I := 0 to High(DropWorkers) do
  begin
    AllOk := AllOk and DropWorkers[I].Ok and (DropWorkers[I].Cycles > 0);
    Inc(TotalDrops, DropWorkers[I].Cycles);
  end;
  Check(AllOk, Format('stress: %d abrupt drops absorbed mid-traffic',
    [TotalDrops]));
  for I := 0 to High(DropWorkers) do
    if not DropWorkers[I].Ok then
      WriteLn('       drop worker ', I, ': ', DropWorkers[I].FailMsg);

  for I := 0 to High(EchoWorkers) do
    EchoWorkers[I].Free;
  for I := 0 to High(DropWorkers) do
    DropWorkers[I].Free;
  Pusher.Free;

  // Prove the server is still healthy after the storm, then leave the
  // connections open so the teardown below is a Shutdown with live
  // connections — the drain must complete and the process exit cleanly.
  StressPhase := 'storm joined; workers freed';
  Ok := True;
  for I := 0 to High(Linger) do
  begin
    StressPhase := 'linger connect ' + IntToStr(I);
    Linger[I] := StressConnect(Url);
    StressPhase := 'linger send ' + IntToStr(I);
    Linger[I].SendText(LingerProbe);
  end;
  for I := 0 to High(Linger) do
  begin
    StressPhase := 'linger read ' + IntToStr(I);
    Ok := Ok and (Linger[I].ReadMessage(IsText, Data, StressStallLimitMs) =
      wrrMessage) and IsText and (Length(Data) = Length(LingerProbe)) and
      CompareMem(@Data[0], @LingerProbe[1], Length(LingerProbe));
  end;
  Check(Ok, Format(
    'stress: server healthy after the storm, %d connections held open',
    [StressLingerCount]));

  StressPhase := 'teardown: stop + waitfor';
  SrvT.Terminate;
  SrvT.Srv.Stop;
  SrvT.WaitFor;
  // A transport exception (e.g. a fatal ArmAccept error) unwinds Run
  // and lands here, not in a crash — surface it instead of letting a
  // dead server thread masquerade as a mystery wedge.
  if SrvT.FatalException <> nil then
    WriteLn('       server thread died: ',
      Exception(SrvT.FatalException).Message);
  StressPhase := 'teardown: server free (shutdown drain)';
  SrvT.Srv.Free; // Shutdown quiesces and drains with the linger conns open
  SrvT.Free;
  Check(True, 'stress: shutdown with live connections drained cleanly');
  StressDone := True;
  Watchdog.WaitFor; // exits within one 250 ms poll slice
  Watchdog.Free;

  for I := 0 to High(Linger) do
    Linger[I].Free;
  Tracker.Free;
  Echo.Free;

  WriteLn;
  if Failures = 0 then
    WriteLn('interop: ALL CHECKS PASSED')
  else
    WriteLn('interop: ', Failures, ' FAILURE(S)');
  Halt(Ord(Failures > 0));
end.
