{ WS.Clock.Test — the deadline clock: it never runs backwards across a
  burst of reads, and it advances by roughly the time actually slept, so
  the Darwin CLOCK_UPTIME_RAW path is scaled to milliseconds rather than
  nanoseconds or seconds. }

program WS.Clock.Test;

{$I Shared.inc}

uses
  SysUtils,

  TestingPascalLibrary,
  WS.Clock;

type
  TMonotonicClock = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestNeverBackwards;
    procedure TestAdvancesInMilliseconds;
  end;

const
  Reads = 100000;
  SleepMs = 200;
  // Windows' native tick advances in ~15.6 ms steps, so an exact sleep
  // can read up to one step short.
  TickGranularityMs = 20;
  // Generous upper bound: a loaded CI runner can oversleep, but not by
  // a factor that a nanosecond or microsecond scaling slip would hide in.
  SleepSlackMs = 2000;

procedure TMonotonicClock.TestNeverBackwards;
var
  Prev, Now_: UInt64;
  I: Integer;
  Backwards: Integer;
begin
  Backwards := 0;
  Prev := WSMonotonicMs;
  for I := 1 to Reads do
  begin
    Now_ := WSMonotonicMs;
    if Now_ < Prev then Inc(Backwards);
    Prev := Now_;
  end;
  Expect<Integer>(Backwards).ToBe(0);
end;

procedure TMonotonicClock.TestAdvancesInMilliseconds;
var
  Start, Elapsed: UInt64;
begin
  Start := WSMonotonicMs;
  Sleep(SleepMs);
  Elapsed := WSMonotonicMs - Start;
  Expect<Boolean>(Elapsed >= SleepMs - TickGranularityMs).ToBe(True);
  Expect<Boolean>(Elapsed < SleepMs + SleepSlackMs).ToBe(True);
end;

procedure TMonotonicClock.SetupTests;
begin
  Test('never runs backwards across a burst of reads', TestNeverBackwards);
  Test('advances by the time slept, in milliseconds',  TestAdvancesInMilliseconds);
end;

begin
  TestRunnerProgram.AddSuite(TMonotonicClock.Create('Clock: monotonic milliseconds'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
