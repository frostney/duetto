{ WS.Transport.PostQueue.Test — the queue is the only piece of the
  cross-thread Post machinery that is platform-neutral, so it gets the
  direct coverage: FIFO order, drain ownership, the Stop rendezvous
  (pending nodes handed back exactly once, later pushes refused), and a
  hammering multi-producer run asserting mutual exclusion plus
  per-producer order — the ordering guarantee TWSConnection.Post
  documents. Transport delivery on top of it is exercised by wsinterop
  over real sockets. }

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

procedure TPostQueueConcurrency.TestPerProducerOrderUnderContention;
const
  Producers = 4;
  PerProducer = 5000;
var
  Q: TWSPostQueue;
  Threads: array[0..Producers - 1] of TPusherThread;
  NextSeq: array[0..Producers - 1] of PtrUInt;
  Node, Head, Next: PWSPostNode;
  I, Total: Integer;
  OrderOk: Boolean;
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
        I := Integer(Node^.ConnId);
        OrderOk := OrderOk and (PtrUInt(Node^.Data) = NextSeq[I]);
        Inc(NextSeq[I]);
        Next := Node^.Next;
        Dispose(Node);
        Node := Next;
      end;
    end;

    for I := 0 to Producers - 1 do
    begin
      Threads[I].WaitFor;
      Expect<Integer>(Threads[I].Accepted).ToBe(PerProducer);
      Threads[I].Free;
    end;
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
// fates — accepted (its node is in a drained chain or the Stop chain,
// exactly once) or refused (the producer kept ownership; the node never
// appears). Nothing is lost, nothing arrives twice, nothing lands after
// Stop.
procedure TPostQueueConcurrency.TestPushRacingStop;
const
  Producers = 4;
  PerProducer = 20000;
var
  Q: TWSPostQueue;
  Threads: array[0..Producers - 1] of TPusherThread;
  Node: PWSPostNode;
  Head: PWSPostNode;
  I, Delivered, AcceptedSum: Integer;
begin
  Q := TWSPostQueue.Create;
  try
    for I := 0 to Producers - 1 do
    begin
      Threads[I] := TPusherThread.Create(True);
      Threads[I].Queue := Q;
      Threads[I].ProducerId := NativeUInt(I);
      Threads[I].Count := PerProducer;
    end;
    for I := 0 to Producers - 1 do
      Threads[I].Start;

    // Stop lands mid-flight; the producers keep hammering into the
    // refusal path until they finish.
    Sleep(5);
    Delivered := 0;
    Head := Q.Stop;
    Node := Head;
    while Node <> nil do
    begin
      Inc(Delivered);
      Node := Node^.Next;
    end;
    FreeChain(Head);

    AcceptedSum := 0;
    for I := 0 to Producers - 1 do
    begin
      Threads[I].WaitFor;
      Inc(AcceptedSum, Threads[I].Accepted);
      Threads[I].Free;
    end;
    // Every accepted push is in the Stop chain exactly once...
    Expect<Integer>(Delivered).ToBe(AcceptedSum);
    // ...and nothing leaks in after it.
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
