{ WS.Transport.PostQueue.Test — the queue is the only piece of the
  cross-thread Post machinery that is platform-neutral, so it gets the
  direct coverage: FIFO order, drain ownership, the Stop rendezvous
  (pending nodes handed back exactly once, later pushes refused), and two
  hammering multi-producer runs that assert the observable properties the
  locking exists for — no accepted push is lost or duplicated, and each
  producer's sequence arrives in exactly the order it pushed (the
  ordering guarantee TWSConnection.Post documents). Mutual exclusion is
  never asserted directly, only through those consequences. Transport
  delivery on top of the queue is exercised by wsinterop over real
  sockets. }

program WS.Transport.PostQueue.Test;

{$I Shared.inc}

uses
  {$ifdef UNIX} cthreads, {$endif}
  Classes,
  SysUtils,

  TestingPascalLibrary,
  WS.Transport.PostQueue;

type
  TPostQueueBasics = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestFifoOrder;
    procedure TestDrainDetaches;
    procedure TestStopReturnsPendingOnce;
    procedure TestPushAfterStopRefused;
  end;

  TPostQueueConcurrency = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestPerProducerOrderUnderContention;
    procedure TestPushRacingStop;
  end;

  TPusherThread = class(TThread)
  public
    Queue: TWSPostQueue;
    ProducerId: NativeUInt;
    Count: Integer;
    Accepted: Integer;
    procedure Execute; override;
  end;

  // Pushes its sequence until the queue refuses, so Stop is guaranteed a
  // live producer to race. Cap is a runaway guard, not the expected exit.
  // Producers spin on StartGate before the first push: releasing them
  // together makes the pre-Stop window a fixed few milliseconds for
  // every producer, so no early starter can reach the cap while the
  // scheduler is still warming a late one up (the exact interleaving a
  // slow Windows VM produced — Sleep(1) there rounds to ~16 ms).
  TRacingPusherThread = class(TThread)
  public
    Queue: TWSPostQueue;
    ProducerId: NativeUInt;
    Cap: Integer;
    StartGate: PBoolean;
    // Published with InterlockedIncrement so the main thread can watch
    // the producers spin up before it lands Stop; final after WaitFor.
    Accepted: LongInt;
    HitCap: Boolean;
    procedure Execute; override;
  end;

procedure FreeChain(ANode: PWSPostNode);
var
  Next: PWSPostNode;
begin
  while ANode <> nil do
  begin
    Next := ANode^.Next;
    Dispose(ANode);
    ANode := Next;
  end;
end;

{ ───────── basics ───────── }

procedure TPostQueueBasics.TestFifoOrder;
var
  Q: TWSPostQueue;
  Node, Head: PWSPostNode;
  I, Got: Integer;
  InOrder: Boolean;
begin
  Q := TWSPostQueue.Create;
  try
    for I := 1 to 100 do
      Expect<Boolean>(Q.Push(NativeUInt(I), Pointer(PtrUInt(I)))).ToBe(True);
    Head := Q.Drain;
    Got := 0;
    InOrder := True;
    Node := Head;
    while Node <> nil do
    begin
      Inc(Got);
      InOrder := InOrder and (Node^.ConnId = NativeUInt(Got)) and
        (Node^.Data = Pointer(PtrUInt(Got)));
      Node := Node^.Next;
    end;
    FreeChain(Head);
    Expect<Integer>(Got).ToBe(100);
    Expect<Boolean>(InOrder).ToBe(True);
  finally
    Q.Free;
  end;
end;

procedure TPostQueueBasics.TestDrainDetaches;
var
  Q: TWSPostQueue;
  Head: PWSPostNode;
begin
  Q := TWSPostQueue.Create;
  try
    Expect<Boolean>(Q.Drain = nil).ToBe(True); // empty drain is nil
    Q.Push(1, nil);
    FreeChain(Q.Drain);
    // The chain was detached, not copied: a second drain owns nothing.
    Expect<Boolean>(Q.Drain = nil).ToBe(True);
    // The queue keeps working after a drain.
    Expect<Boolean>(Q.Push(2, nil)).ToBe(True);
    Head := Q.Drain;
    Expect<Boolean>(Head <> nil).ToBe(True);
    Expect<Boolean>(Head^.ConnId = 2).ToBe(True);
    FreeChain(Head);
  finally
    Q.Free;
  end;
end;

procedure TPostQueueBasics.TestStopReturnsPendingOnce;
var
  Q: TWSPostQueue;
  Node, Head: PWSPostNode;
  Got: Integer;
begin
  Q := TWSPostQueue.Create;
  try
    Q.Push(10, nil);
    Q.Push(11, nil);
    Q.Push(12, nil);
    Head := Q.Stop;
    Got := 0;
    Node := Head;
    while Node <> nil do
    begin
      Inc(Got);
      Node := Node^.Next;
    end;
    FreeChain(Head);
    Expect<Integer>(Got).ToBe(3);
    // Exactly once: a second Stop (idempotent) and a Drain own nothing.
    Expect<Boolean>(Q.Stop = nil).ToBe(True);
    Expect<Boolean>(Q.Drain = nil).ToBe(True);
  finally
    Q.Free;
  end;
end;

procedure TPostQueueBasics.TestPushAfterStopRefused;
var
  Q: TWSPostQueue;
begin
  Q := TWSPostQueue.Create;
  try
    FreeChain(Q.Stop);
    // Refused pushes leave ownership of Data with the caller and queue
    // nothing.
    Expect<Boolean>(Q.Push(1, nil)).ToBe(False);
    Expect<Boolean>(Q.Drain = nil).ToBe(True);
  finally
    Q.Free;
  end;
end;

{ ───────── concurrency ───────── }

procedure TPusherThread.Execute;
var
  I: Integer;
begin
  Accepted := 0;
  for I := 0 to Count - 1 do
    if Queue.Push(ProducerId, Pointer(PtrUInt(I))) then
      Inc(Accepted);
end;

procedure TRacingPusherThread.Execute;
var
  Seq: Integer;
begin
  Accepted := 0;
  HitCap := False;
  // ThreadSwitch is an opaque RTL call, so the gate read cannot be
  // hoisted out of the loop.
  while not StartGate^ do
    ThreadSwitch;
  // Sequence and counter move in lockstep, so the accepted sequences are
  // exactly 0 .. Accepted-1 — the property the Stop chain is checked
  // against.
  Seq := 0;
  while Seq < Cap do
  begin
    if not Queue.Push(ProducerId, Pointer(PtrUInt(Seq))) then Exit;
    Inc(Seq);
    InterlockedIncrement(Accepted);
  end;
  HitCap := True;
end;

procedure TPostQueueConcurrency.TestPerProducerOrderUnderContention;
const
  Producers = 4;
  PerProducer = 5000;
var
  Q: TWSPostQueue;
  Threads: array[0..Producers - 1] of TPusherThread;
  NextSeq: array[0..Producers - 1] of PtrUInt;
  Node, Head, Next: PWSPostNode;
  I, Producer, Total: Integer;
  OrderOk, AcceptedOk: Boolean;
  Deadline: QWord;
begin
  Q := TWSPostQueue.Create;
  try
    for I := 0 to Producers - 1 do
    begin
      Threads[I] := TPusherThread.Create(True);
      Threads[I].Queue := Q;
      Threads[I].ProducerId := NativeUInt(I);
      Threads[I].Count := PerProducer;
      NextSeq[I] := 0;
    end;
    for I := 0 to Producers - 1 do
      Threads[I].Start;

    // Drain concurrently with the pushers — the consumer side of the
    // real transports — checking that every producer's sequence arrives
    // in its push order regardless of interleaving. Deadline-bounded so
    // a lost node fails the assertion below instead of hanging the
    // suite.
    Total := 0;
    OrderOk := True;
    Deadline := GetTickCount64 + 30000;
    while (Total < Producers * PerProducer) and
      (GetTickCount64 < Deadline) do
    begin
      Head := Q.Drain;
      if Head = nil then
      begin
        Sleep(1);
        Continue;
      end;
      Node := Head;
      while Node <> nil do
      begin
        Inc(Total);
        Producer := Integer(Node^.ConnId);
        OrderOk := OrderOk and (PtrUInt(Node^.Data) = NextSeq[Producer]);
        Inc(NextSeq[Producer]);
        Next := Node^.Next;
        Dispose(Node);
        Node := Next;
      end;
    end;

    // Join and free every producer before asserting anything: a raised
    // assertion here would otherwise skip the remaining joins and let
    // the finally below free the queue under threads still pushing into
    // it — a use-after-free instead of a red test.
    AcceptedOk := True;
    for I := 0 to Producers - 1 do
    begin
      Threads[I].WaitFor;
      AcceptedOk := AcceptedOk and (Threads[I].Accepted = PerProducer);
      Threads[I].Free;
    end;
    Expect<Boolean>(AcceptedOk).ToBe(True);
    Expect<Integer>(Total).ToBe(Producers * PerProducer);
    Expect<Boolean>(OrderOk).ToBe(True);
    Expect<Boolean>(Q.Drain = nil).ToBe(True);
  finally
    Q.Free;
  end;
end;

procedure TPostQueueBasics.SetupTests;
begin
  Test('FIFO order preserved through drain',       TestFifoOrder);
  Test('drain detaches the chain',                 TestDrainDetaches);
  Test('stop hands back pending exactly once',     TestStopReturnsPendingOnce);
  Test('push after stop is refused',               TestPushAfterStopRefused);
end;

// The shutdown rendezvous property the transports lean on: with
// producers pushing full-tilt, Stop splits every push into exactly two
// fates — accepted (its node is in the Stop chain, exactly once, in push
// order) or refused (the producer kept ownership; the node never
// appears). Nothing is lost, nothing arrives twice, nothing lands after
// Stop.
//
// Both vacuous outcomes are designed out. The producers push until the
// queue refuses rather than a fixed count, so they cannot finish before
// Stop and leave the refusal path unexercised; and the main thread waits
// for every producer to get well past a spin-up threshold before it
// Stops, so Stop cannot land before the producers were scheduled. The
// run is asserted to have ended by refusal, never by the runaway cap.
procedure TPostQueueConcurrency.TestPushRacingStop;
const
  Producers = 4;
  // Runaway guard only: reaching it means Stop never refused, which the
  // HitCap assertion below turns into a red test. Sized so it is
  // unreachable inside the fixed pre-Stop window: every push crosses
  // one shared critical section, which bounds the aggregate well below
  // Cap-per-producer in tens of milliseconds.
  PushCap = 2000000;
  RaceWindowMs = 10;
  // Generous bound on the scheduler getting the first producer onto a
  // core after the gate opens. Never reached on a healthy machine; it
  // exists so a pathologically starved run fails the assertions below
  // instead of hanging the suite.
  StartupBoundMs = 30000;
var
  Q: TWSPostQueue;
  Threads: array[0..Producers - 1] of TRacingPusherThread;
  NextSeq: array[0..Producers - 1] of PtrUInt;
  Node, Head, Next: PWSPostNode;
  I, Producer, Delivered, AcceptedSum: Integer;
  ExactOk, RefusedOk, CountOk: Boolean;
  Gate, Started: Boolean;
  StartupBound: QWord;
begin
  Q := TWSPostQueue.Create;
  Gate := False;
  try
    for I := 0 to Producers - 1 do
    begin
      Threads[I] := TRacingPusherThread.Create(True);
      Threads[I].Queue := Q;
      Threads[I].ProducerId := NativeUInt(I);
      Threads[I].Cap := PushCap;
      Threads[I].StartGate := @Gate;
      NextSeq[I] := 0;
    end;
    for I := 0 to Producers - 1 do
      Threads[I].Start;

    // Release every producer at once, wait for the first push to
    // actually land, then give the set a fixed window to hammer before
    // landing Stop mid-flight. The bounded wait is what keeps the
    // barrier's cap safety without the all-four-starved flake: a
    // producer the scheduler starves for the window is simply refused
    // at its first push (Accepted = 0), a valid outcome — but ALL FOUR
    // starved means Stop lands on an empty queue and AcceptedSum = 0
    // fails a run that proved nothing. The wait is on the aggregate, so
    // the race the fixed window creates is unchanged.
    Gate := True;
    StartupBound := GetTickCount64 + StartupBoundMs;
    repeat
      Started := False;
      for I := 0 to Producers - 1 do
        if InterlockedExchangeAdd(Threads[I].Accepted, 0) > 0 then
          Started := True;
      if Started then Break;
      Sleep(1);
    until GetTickCount64 >= StartupBound;
    Sleep(RaceWindowMs);
    Head := Q.Stop;

    // Join and free every producer before asserting: an assertion that
    // raised here would skip the remaining joins and let the finally
    // below free the queue under live producers.
    AcceptedSum := 0;
    RefusedOk := True;
    for I := 0 to Producers - 1 do
    begin
      Threads[I].WaitFor;
      Inc(AcceptedSum, Threads[I].Accepted);
      RefusedOk := RefusedOk and not Threads[I].HitCap;
      NextSeq[I] := 0;
    end;

    // No pre-Stop drain, so the Stop chain must hold every accepted
    // push: per producer exactly the sequences 0 .. Accepted-1, each
    // once, in push order. Walking it and expecting the next sequence
    // per producer checks order, absence of loss and absence of
    // duplication in one pass; the per-producer totals below close it.
    Delivered := 0;
    ExactOk := True;
    Node := Head;
    while Node <> nil do
    begin
      Inc(Delivered);
      Producer := Integer(Node^.ConnId);
      if (Producer < 0) or (Producer >= Producers) then
        ExactOk := False
      else
      begin
        ExactOk := ExactOk and (PtrUInt(Node^.Data) = NextSeq[Producer]);
        Inc(NextSeq[Producer]);
      end;
      Next := Node^.Next;
      Dispose(Node);
      Node := Next;
    end;
    CountOk := True;
    for I := 0 to Producers - 1 do
      CountOk := CountOk and (NextSeq[I] = PtrUInt(Threads[I].Accepted));
    for I := 0 to Producers - 1 do
      Threads[I].Free;

    Expect<Boolean>(RefusedOk).ToBe(True);     // ended by refusal, not cap
    Expect<Boolean>(AcceptedSum > 0).ToBe(True);
    Expect<Integer>(Delivered).ToBe(AcceptedSum);
    Expect<Boolean>(ExactOk).ToBe(True);
    Expect<Boolean>(CountOk).ToBe(True);
    // Nothing leaks in after Stop.
    Expect<Boolean>(Q.Drain = nil).ToBe(True);
    Expect<Boolean>(Q.Stop = nil).ToBe(True);
  finally
    Q.Free;
  end;
end;

procedure TPostQueueConcurrency.SetupTests;
begin
  Test('per-producer order under contention',      TestPerProducerOrderUnderContention);
  Test('push racing stop: accepted xor refused',   TestPushRacingStop);
end;

begin
  TestRunnerProgram.AddSuite(TPostQueueBasics.Create('PostQueue: basics'));
  TestRunnerProgram.AddSuite(TPostQueueConcurrency.Create('PostQueue: concurrency'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
