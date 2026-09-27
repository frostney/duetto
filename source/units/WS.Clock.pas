unit WS.Clock;

// The monotonic millisecond clock behind every deadline in the library:
// session clocks, close drains, handshake budgets, accept backoff and the
// client's bounded read.
//
// FPC 3.2.2's SysUtils.GetTickCount64 is monotonic on Linux
// (clock_gettime(CLOCK_MONOTONIC)) and Windows (the native call), but
// rtl/unix/sysutils.pp only enables clock_gettime for Linux and FreeBSD;
// everywhere else, macOS included, it falls back to gettimeofday. A
// wall-clock step would then delay every armed deadline or fire them all
// at once, so Darwin reads CLOCK_UPTIME_RAW instead (the mach_absolute_time
// clock, which like Linux's CLOCK_MONOTONIC does not advance in sleep).

{$I Shared.inc}

interface

// Milliseconds from an arbitrary fixed origin; never goes backwards.
function WSMonotonicMs: UInt64;

implementation

uses
  SysUtils;

{$ifdef DARWIN}
const
  // CLOCK_UPTIME_RAW from <time.h>.
  ClockUptimeRaw = 8;
  NanosecondsPerMillisecond = 1000000;

function Clock_gettime_nsec_np(AClockId: Integer): UInt64; cdecl; external 'c' name 'clock_gettime_nsec_np';

function WSMonotonicMs: UInt64;
begin
  Result := Clock_gettime_nsec_np(ClockUptimeRaw) div NanosecondsPerMillisecond;
end;
{$else}

function WSMonotonicMs: UInt64;
begin
  Result := GetTickCount64;
end;
{$endif}

end.
