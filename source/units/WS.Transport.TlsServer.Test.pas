{ WS.Transport.TlsServer.Test — the platform-neutral halves of the
  server-TLS session layer.

  Two things in that unit are pure and therefore directly testable on
  every platform, including macOS where the OpenSSL accept backend does
  not exist at all:

    - WSTlsResolvePolicy, which turns a TWSTransportTls record into a
      validated flow-control policy. Input and output capacities are
      independent, the low watermark is derived from (and checked
      against) the high one, and every zero means "default" — the
      configuration contract issue #22 asks to be proven.
    - TWSTlsCarry, the re-offer buffer that holds ciphertext lwpt would
      not accept. Its whole job is to lose nothing, duplicate nothing
      and reorder nothing across arbitrary short accepts, and to stop
      growing once a consumed prefix can be compacted away.

  Everything above those — the handshake pump, the backpressure
  transitions, close_notify — needs a live OpenSSL peer, so it is
  proven end to end by the wsinterop TLS section (Linux) rather than
  faked with a stub here. }

program WS.Transport.TlsServer.Test;

{$I Shared.inc}

uses
  SysUtils,

  TestingPascalLibrary,
  TransportSecurity,
  WS.Transport,
  WS.Transport.TlsServer;

type
  TTlsPolicyTests = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestZeroesResolveToDefaults;
    procedure TestCapacitiesAreIndependent;
    procedure TestLowWaterDefaultsToHalf;
    procedure TestLowWaterMustBeBelowHigh;
    procedure TestInputRangeEnforced;
    procedure TestOutputRangeEnforced;
    procedure TestGuardDefaultsAndFloor;
    procedure TestBudgetTracksWidenedInput;
    procedure TestContextGuards;
  end;

  TTlsCarryTests = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestEmptyCarryIsNil;
    procedure TestAppendConsumePreservesOrder;
    procedure TestPartialConsumeRefeedsTheTail;
    procedure TestCompactionBoundsGrowth;
    procedure TestShrinkOnDrain;
    procedure TestResetReleases;
  end;

// A record with only Enabled set — the shape every caller starts from.
function BareTls: TWSTransportTls;
begin
  Result := WSTransportNoTls;
  Result.Enabled := True;
  Result.Pkcs12Path := 'identity.p12';
end;

function ResolveRaises(const ATls: TWSTransportTls): Boolean;
var
  Policy: TWSTlsPolicy;
begin
  Result := False;
  try
    Policy := WSTlsResolvePolicy(ATls);
    // Silences the "assigned but never used" hint without weakening
    // the check: reaching here at all is the failure.
    Result := Policy.InputHighWater < 0;
  except
    on EWSTlsServer do
      Result := True;
  end;
end;

// True when WSTlsCreateServerContext rejects the configuration at one of
// its pure guards. Both guards fire BEFORE any OpenSSL context is built,
// so these cases are platform-independent (they never reach the macOS
// "server TLS unsupported" path).
function CreateContextRaises(const ATls: TWSTransportTls): Boolean;
var
  Context: TTransportSecurityServerContext;
  Policy: TWSTlsPolicy;
begin
  Result := False;
  FillChar(Policy, SizeOf(Policy), 0);
  Context := nil;
  try
    Context := WSTlsCreateServerContext(ATls, Policy);
    // Reaching here means no guard fired; reclaim whatever came back so
    // the check itself leaks nothing.
    if Context <> nil then
      CloseTransportSecurityServerContext(Context);
  except
    on EWSTlsServer do
      Result := True;
  end;
end;

{ ───────── policy ───────── }

procedure TTlsPolicyTests.TestZeroesResolveToDefaults;
var
  Policy: TWSTlsPolicy;
begin
  Policy := WSTlsResolvePolicy(BareTls);
  Expect<Integer>(Policy.InputHighWater).ToBe(TLS_SERVER_DEFAULT_INPUT_CAPACITY);
  Expect<Integer>(Policy.InputLowWater).ToBe(
    TLS_SERVER_DEFAULT_INPUT_CAPACITY div 2);
  Expect<Integer>(Policy.OutputCapacity).ToBe(
    TLS_SERVER_DEFAULT_OUTPUT_CAPACITY);
  Expect<Integer>(Policy.HandshakeDeadlineMs).ToBe(
    WSTlsDefaultHandshakeDeadlineMs);
  Expect<Integer>(Policy.InboundHandshakeBudget).ToBe(
    WSTlsDefaultInboundHandshakeBudget);
end;

// The point of lwpt#85: one capacity moving must not drag the other.
procedure TTlsPolicyTests.TestCapacitiesAreIndependent;
var
  Tls: TWSTransportTls;
  Policy: TWSTlsPolicy;
begin
  Tls := BareTls;
  Tls.InputHighWater := TLS_SERVER_MIN_INPUT_CAPACITY;
  Policy := WSTlsResolvePolicy(Tls);
  Expect<Integer>(Policy.InputHighWater).ToBe(TLS_SERVER_MIN_INPUT_CAPACITY);
  Expect<Integer>(Policy.OutputCapacity).ToBe(
    TLS_SERVER_DEFAULT_OUTPUT_CAPACITY);

  Tls := BareTls;
  Tls.OutputCapacity := TLS_SERVER_MAX_OUTPUT_CAPACITY;
  Policy := WSTlsResolvePolicy(Tls);
  Expect<Integer>(Policy.OutputCapacity).ToBe(TLS_SERVER_MAX_OUTPUT_CAPACITY);
  Expect<Integer>(Policy.InputHighWater).ToBe(
    TLS_SERVER_DEFAULT_INPUT_CAPACITY);
  Expect<Integer>(Policy.InputLowWater).ToBe(
    TLS_SERVER_DEFAULT_INPUT_CAPACITY div 2);
end;

procedure TTlsPolicyTests.TestLowWaterDefaultsToHalf;
var
  Tls: TWSTransportTls;
  Policy: TWSTlsPolicy;
begin
  Tls := BareTls;
  Tls.InputHighWater := 40 * 1024;
  Policy := WSTlsResolvePolicy(Tls);
  Expect<Integer>(Policy.InputLowWater).ToBe(20 * 1024);

  // An explicit low watermark survives untouched.
  Tls.InputLowWater := 1024;
  Policy := WSTlsResolvePolicy(Tls);
  Expect<Integer>(Policy.InputLowWater).ToBe(1024);
  Expect<Integer>(Policy.InputHighWater).ToBe(40 * 1024);
end;

procedure TTlsPolicyTests.TestLowWaterMustBeBelowHigh;
var
  Tls: TWSTransportTls;
begin
  Tls := BareTls;
  Tls.InputHighWater := 40 * 1024;
  Tls.InputLowWater := 40 * 1024; // equal: no hysteresis at all
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(True);
  Tls.InputLowWater := 64 * 1024; // above the high watermark
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(True);
  Tls.InputLowWater := -1;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(True);
  Tls.InputLowWater := 40 * 1024 - 1; // the last legal value
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(False);
end;

procedure TTlsPolicyTests.TestInputRangeEnforced;
var
  Tls: TWSTransportTls;
begin
  Tls := BareTls;
  Tls.InputHighWater := TLS_SERVER_MIN_INPUT_CAPACITY - 1;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(True);
  Tls.InputHighWater := TLS_SERVER_MAX_INPUT_CAPACITY + 1;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(True);
  Tls.InputHighWater := TLS_SERVER_MIN_INPUT_CAPACITY;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(False);
  Tls.InputHighWater := TLS_SERVER_MAX_INPUT_CAPACITY;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(False);
end;

procedure TTlsPolicyTests.TestOutputRangeEnforced;
var
  Tls: TWSTransportTls;
begin
  Tls := BareTls;
  Tls.OutputCapacity := TLS_SERVER_MIN_OUTPUT_CAPACITY - 1;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(True);
  Tls.OutputCapacity := TLS_SERVER_MAX_OUTPUT_CAPACITY + 1;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(True);
  Tls.OutputCapacity := TLS_SERVER_MIN_OUTPUT_CAPACITY;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(False);
end;

procedure TTlsPolicyTests.TestGuardDefaultsAndFloor;
var
  Tls: TWSTransportTls;
  Policy: TWSTlsPolicy;
begin
  Tls := BareTls;
  Tls.HandshakeDeadlineMs := 750;
  Tls.InboundHandshakeBudget := 128 * 1024;
  Policy := WSTlsResolvePolicy(Tls);
  Expect<Integer>(Policy.HandshakeDeadlineMs).ToBe(750);
  Expect<Integer>(Policy.InboundHandshakeBudget).ToBe(128 * 1024);

  // A negative deadline is a configuration error, not "no deadline".
  Tls := BareTls;
  Tls.HandshakeDeadlineMs := -1;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(True);

  // A budget under the input high watermark could reject a handshake
  // the input buffer was sized to hold.
  Tls := BareTls;
  Tls.InputHighWater := 64 * 1024;
  Tls.InboundHandshakeBudget := 32 * 1024;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(True);
  Tls.InboundHandshakeBudget := 64 * 1024;
  Expect<Boolean>(ResolveRaises(Tls)).ToBe(False);
end;

// A high watermark above the fixed 64 KiB default pulls the resolved
// zero-budget default up with it, so the budget never rejects a
// handshake the widened input buffer was sized to hold — the exact
// value the raise message now reports as the resolved default.
procedure TTlsPolicyTests.TestBudgetTracksWidenedInput;
var
  Tls: TWSTransportTls;
  Policy: TWSTlsPolicy;
begin
  Tls := BareTls;
  Tls.InputHighWater := 128 * 1024; // within lwpt's 256 KiB ceiling
  Policy := WSTlsResolvePolicy(Tls);
  Expect<Integer>(Policy.InboundHandshakeBudget).ToBe(128 * 1024);
end;

// The two pure guards on the context builder: TLS must be enabled and an
// identity path must be named. Both reject before any backend work, so
// the listener fails at construction rather than the first handshake.
procedure TTlsPolicyTests.TestContextGuards;
var
  Tls: TWSTransportTls;
begin
  Tls := BareTls;
  Tls.Enabled := False;
  Expect<Boolean>(CreateContextRaises(Tls)).ToBe(True);

  Tls := BareTls;
  Tls.Pkcs12Path := '';
  Expect<Boolean>(CreateContextRaises(Tls)).ToBe(True);
end;

procedure TTlsPolicyTests.SetupTests;
begin
  Test('zero fields resolve to the documented defaults',
    TestZeroesResolveToDefaults);
  Test('input and output capacities are independent',
    TestCapacitiesAreIndependent);
  Test('low watermark defaults to half the high one',
    TestLowWaterDefaultsToHalf);
  Test('low watermark must sit below the high one',
    TestLowWaterMustBeBelowHigh);
  Test('input capacity is range-checked against lwpt',
    TestInputRangeEnforced);
  Test('output capacity is range-checked against lwpt',
    TestOutputRangeEnforced);
  Test('handshake deadline and inbound budget defaults and floor',
    TestGuardDefaultsAndFloor);
  Test('inbound budget default tracks a widened input high watermark',
    TestBudgetTracksWidenedInput);
  Test('context builder rejects disabled TLS and a missing identity',
    TestContextGuards);
end;

{ ───────── carry buffer ───────── }

// Deterministic filler so a reordered or duplicated byte is visible.
function Pattern(AStart, ALen: Integer): TBytes;
var
  I: Integer;
begin
  SetLength(Result, ALen);
  for I := 0 to ALen - 1 do
    Result[I] := Byte((AStart + I) * 37 + 11);
end;

procedure TTlsCarryTests.TestEmptyCarryIsNil;
var
  Carry: TWSTlsCarry;
begin
  Carry.Reset;
  Expect<Boolean>(Carry.Head = nil).ToBe(True);
  Expect<Integer>(Integer(Carry.Len)).ToBe(0);
  // Degenerate offers are no-ops, not corruption.
  Carry.Append(nil, 16);
  Carry.Consume(0);
  Carry.Consume(-5);
  Expect<Integer>(Integer(Carry.Len)).ToBe(0);
  Expect<Boolean>(Carry.Head = nil).ToBe(True);
end;

procedure TTlsCarryTests.TestAppendConsumePreservesOrder;
var
  Carry: TWSTlsCarry;
  A, B: TBytes;
  I: Integer;
  Ok: Boolean;
begin
  Carry.Reset;
  A := Pattern(0, 100);
  B := Pattern(100, 60);
  Carry.Append(@A[0], Length(A));
  Carry.Append(@B[0], Length(B));
  Expect<Integer>(Integer(Carry.Len)).ToBe(160);
  Ok := True;
  for I := 0 to 159 do
    Ok := Ok and (Carry.Head[I] = Byte(I * 37 + 11));
  Expect<Boolean>(Ok).ToBe(True);
  Carry.Consume(160);
  Expect<Integer>(Integer(Carry.Len)).ToBe(0);
  Expect<Boolean>(Carry.Head = nil).ToBe(True);
end;

// The re-offer contract: lwpt takes a prefix, the rest stays queued in
// wire order and is offered again before anything newer.
procedure TTlsCarryTests.TestPartialConsumeRefeedsTheTail;
var
  Carry: TWSTlsCarry;
  Src, Fresh: TBytes;
  Seen: TBytes;
  Taken, Total: Integer;
  I: Integer;
  Ok, Added: Boolean;
begin
  Carry.Reset;
  Src := Pattern(0, 500);
  Carry.Append(@Src[0], Length(Src));

  // Drain in a ragged pattern, mixing a fresh append in mid-flight —
  // exactly what Ingest does when a backpressured connection is handed
  // more socket bytes.
  SetLength(Seen, 0);
  Total := 0;
  Taken := 7;
  Added := False;
  while Carry.Len > 0 do
  begin
    if Taken > Carry.Len then Taken := Carry.Len;
    SetLength(Seen, Total + Taken);
    Move(Carry.Head^, Seen[Total], Taken);
    Inc(Total, Taken);
    Carry.Consume(Taken);
    if (Total >= 105) and (not Added) then
    begin
      // The tail must queue BEHIND what is still owed, never ahead.
      Added := True;
      Fresh := Pattern(500, 40);
      Carry.Append(@Fresh[0], Length(Fresh));
    end;
    Taken := Taken * 2 + 1;
    if Taken > 64 then Taken := 3;
  end;

  Expect<Integer>(Total).ToBe(540);
  Ok := True;
  for I := 0 to 539 do
    Ok := Ok and (Seen[I] = Byte(I * 37 + 11));
  Expect<Boolean>(Ok).ToBe(True);
end;

// A head that only moves forward would grow the buffer without bound on
// a long-lived backpressured connection; Append compacts first.
procedure TTlsCarryTests.TestCompactionBoundsGrowth;
var
  Carry: TWSTlsCarry;
  Chunk: TBytes;
  I: Integer;
  Peak: NativeInt;
begin
  Carry.Reset;
  Chunk := Pattern(0, 1000);
  Peak := 0;
  for I := 1 to 200 do
  begin
    Carry.Append(@Chunk[0], Length(Chunk));
    Carry.Consume(900); // 100 bytes stay owed every round
    if Carry.Allocated > Peak then Peak := Carry.Allocated;
  end;
  Expect<Integer>(Integer(Carry.Len)).ToBe(100 * 200);
  // ~20 KB of live backlog, and the allocation tracks THAT rather than
  // the ~200 KB that passed through. The bound is the live backlog plus
  // one chunk of headroom — a slack loose enough to survive compaction
  // rounding but ~10x tighter than the peak throughput, so it still
  // fails outright if compaction is removed (the buffer would then track
  // the 200 KB total, not the 20 KB owed).
  Expect<Boolean>(Peak < Carry.Len + 2000).ToBe(True);
end;

// A spike into a large backlog must not be retained for the connection's
// life: once the backlog drains to empty, the allocation is released
// (down to at most the shrink floor) rather than pinned at high water.
procedure TTlsCarryTests.TestShrinkOnDrain;
var
  Carry: TWSTlsCarry;
  Chunk: TBytes;
begin
  Carry.Reset;
  Chunk := Pattern(0, 200 * 1024);
  Carry.Append(@Chunk[0], Length(Chunk));
  Expect<Boolean>(Carry.Allocated >= 200 * 1024).ToBe(True);
  // Drain the whole spike. The buffer empties, so the allocation is let
  // go instead of surviving at 200 KB.
  Carry.Consume(Carry.Len);
  Expect<Integer>(Integer(Carry.Len)).ToBe(0);
  Expect<Boolean>(Carry.Allocated <= WSTlsCarryShrinkFloor).ToBe(True);
  // Still usable — Append re-grows on demand.
  Carry.Append(@Chunk[0], 10);
  Expect<Integer>(Integer(Carry.Len)).ToBe(10);
end;

procedure TTlsCarryTests.TestResetReleases;
var
  Carry: TWSTlsCarry;
  Chunk: TBytes;
begin
  Carry.Reset;
  Chunk := Pattern(0, 4096);
  Carry.Append(@Chunk[0], Length(Chunk));
  Expect<Boolean>(Carry.Allocated >= 4096).ToBe(True);
  Carry.Reset;
  Expect<Integer>(Integer(Carry.Len)).ToBe(0);
  Expect<Integer>(Integer(Carry.Allocated)).ToBe(0);
  // Usable again after a reset — the failure path reuses the record.
  Carry.Append(@Chunk[0], 10);
  Expect<Integer>(Integer(Carry.Len)).ToBe(10);
end;

procedure TTlsCarryTests.SetupTests;
begin
  Test('an empty carry yields nil and shrugs off degenerate calls',
    TestEmptyCarryIsNil);
  Test('appends come back in wire order', TestAppendConsumePreservesOrder);
  Test('a partial accept re-offers the tail, new bytes queue behind it',
    TestPartialConsumeRefeedsTheTail);
  Test('compaction bounds growth across many partial accepts',
    TestCompactionBoundsGrowth);
  Test('a fully drained buffer releases a spike allocation',
    TestShrinkOnDrain);
  Test('reset releases the buffer and stays usable', TestResetReleases);
end;

begin
  TestRunnerProgram.AddSuite(TTlsPolicyTests.Create('TlsServer: policy'));
  TestRunnerProgram.AddSuite(TTlsCarryTests.Create('TlsServer: carry buffer'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
