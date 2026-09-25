program wsbench;

// Component benchmarks for every duetto layer, bottom-up:
//
//   masking      — naive byte loop vs UInt64 XOR vs SSE2 (GB/s)
//   frame parse  — ParseFrameHeader over a packed stream (frames/s)
//   utf-8        — fast-path Utf8Advance vs pure-DFA, ASCII + multibyte
//   handshake    — ServerParseRequest + ServerBuildResponse (ops/s)
//   deflate      — RFC 7692 compress / inflate (MB/s)
//   protocol     — two TWSProtocol machines piped back-to-back: a full
//                  in-process echo round-trip per iteration, masking,
//                  parsing, validating and unmasking on both sides.
//                  This is the network-free ceiling of the library.
//
// Methodology: each subject runs for tens of milliseconds or more on a
// microsecond clock (the masking loops repeat until MaskSecs has passed);
// single runs, no medians — run it more than once on a quiet machine and
// compare. Numbers are only meaningful from a release build
// (`lwpt build --mode release`): a dev build keeps range and overflow
// checks on, and the banner says which one is running.

{$I Shared.inc}

uses
  {$ifdef LINUX} Linux, {$endif}
  {$ifdef UNIX} BaseUnix, Unix, {$endif}
  {$ifdef WINDOWS} Windows, {$endif}
  SysUtils, WS.Frame, WS.Utf8, WS.Handshake, WS.Deflate, WS.Protocol;

const
  MaskSecs = 0.5;
  BenchMaskKey = $12345678;

var
  T0: Int64;

// Microseconds. SysUtils.Now ticks in whole milliseconds, which turned a
// 10-19 ms masking pass into a reading quantised to whole-millisecond
// steps (100 / 90.9 / 55.6 GB/s); these clocks resolve to a microsecond
// or better. Monotonic on Linux and Windows; macOS falls back to
// gettimeofday.
function Now64: Int64;
{$if defined(LINUX)}
var
  Ts: TTimeSpec;
begin
  clock_gettime(CLOCK_MONOTONIC, @Ts);
  Result := Int64(Ts.tv_sec) * 1000000 + Ts.tv_nsec div 1000;
end;
{$elseif defined(UNIX)}
var
  Tv: TTimeVal;
begin
  fpgettimeofday(@Tv, nil);
  Result := Int64(Tv.tv_sec) * 1000000 + Tv.tv_usec;
end;
{$else}
var
  Count, Freq: Int64;
begin
  QueryPerformanceCounter(Count);
  QueryPerformanceFrequency(Freq);
  Result := Round(Count / Freq * 1e6);
end;
{$endif}

type
  TMaskProc = procedure(P: PByte; ALen: PtrUInt; ARotKey: UInt32);

// Repeats AProc over the whole buffer until MaskSecs has passed; GB/s.
function TimeMask(AProc: TMaskProc; ABuf: PByte; ASize: PtrUInt): Double;
var
  T, Deadline: Int64;
  Reps: Int64;
begin
  Reps := 0;
  T := Now64;
  Deadline := T + Round(MaskSecs * 1e6);
  repeat
    AProc(ABuf, ASize, BenchMaskKey);
    Inc(Reps);
  until Now64 >= Deadline;
  Result := ASize / (1024.0 * 1024 * 1024) * Reps / ((Now64 - T) / 1e6);
end;

procedure BenchMasking;
const
  SIZE = 16 * 1024 * 1024;
var
  Buf: TBytes;
  I: Integer;
  Sum: Byte;
begin
  SetLength(Buf, SIZE);
  for I := 0 to SIZE - 1 do Buf[I] := Byte(I);
  WriteLn(Format('-- masking (%d MiB, repeated for %.1f s each) --',
    [SIZE div (1024 * 1024), MaskSecs]));

  UnmaskNaive(PByte(Buf), SIZE, BenchMaskKey); // warm
  WriteLn(Format('naive   : %8.2f GB/s', [TimeMask(UnmaskNaive, PByte(Buf), SIZE)]));
  WriteLn(Format('uint64  : %8.2f GB/s', [TimeMask(UnmaskU64, PByte(Buf), SIZE)]));
  // UnmaskSSE2 only exists where WS.Frame compiles it (x86_64 Linux).
  {$if defined(CPUX86_64) and defined(LINUX)}
  WriteLn(Format('sse2    : %8.2f GB/s', [TimeMask(UnmaskSSE2, PByte(Buf), SIZE)]));
  {$endif}

  // keep the work observable
  Sum := 0;
  for I := 0 to 63 do Sum := Sum xor Buf[I];
  if Sum = 173 then Write('');
end;

procedure BenchFrameParse;
const
  NFRAMES = 200000;
  ROUNDS = 20;
var
  Stream: TBytes;
  Pos: NativeInt;
  I, R: Integer;
  H: TWSFrameHeader;
  T: Int64;
  Secs: Double;
  Parsed: Int64;
  Hdr: array[0..WS_MAX_HEADER - 1] of Byte;
  HLen: Integer;
  Sizes: array[0..3] of Integer = (5, 125, 126, 1000);
begin
  // Pack a stream of headers+payloads with mixed length encodings.
  SetLength(Stream, NFRAMES * 16 + (NFRAMES div 4 + 1) * (5 + 125 + 126 + 1000));
  Pos := 0;
  for I := 0 to NFRAMES - 1 do
  begin
    HLen := WriteFrameHeader(@Hdr[0], True, False, WS_OP_BINARY, True,
      $DEADBEEF, Sizes[I and 3]);
    Move(Hdr[0], Stream[Pos], HLen);
    Inc(Pos, HLen + Sizes[I and 3]); // skip payload bytes (left zero)
  end;
  SetLength(Stream, Pos);

  WriteLn('-- frame header parse (mixed 7/16-bit lengths) --');
  Parsed := 0;
  T := Now64;
  for R := 1 to ROUNDS do
  begin
    Pos := 0;
    while Pos < Length(Stream) do
    begin
      if ParseFrameHeader(@Stream[Pos], Length(Stream) - Pos, H) <> wprOK then
        Halt(9);
      Inc(Pos, H.HeaderLen + NativeInt(H.PayloadLen));
      Inc(Parsed);
    end;
  end;
  Secs := (Now64 - T) / 1e6;
  WriteLn(Format('parse   : %8.1f M frames/s', [Parsed / 1e6 / Secs]));
end;

procedure BenchUtf8;
const
  SIZE = 8 * 1024 * 1024;
  REPS = 40;
var
  Ascii, Multi: TBytes;
  I, R: Integer;
  T: Int64;
  St: UInt32;
  Secs: Double;
  P: NativeInt;
begin
  SetLength(Ascii, SIZE);
  for I := 0 to SIZE - 1 do Ascii[I] := 32 + (I mod 90);
  // alternating 3-byte CJK + ASCII
  SetLength(Multi, SIZE);
  P := 0;
  while P + 4 <= SIZE do
  begin
    Multi[P] := $E4; Multi[P + 1] := $B8; Multi[P + 2] := $AD; Multi[P + 3] := 65;
    Inc(P, 4);
  end;
  while P < SIZE do begin Multi[P] := 65; Inc(P); end;

  WriteLn('-- utf-8 validation (', SIZE div (1024 * 1024), ' MiB x ', REPS, ') --');
  St := 0;
  if not Utf8Advance(St, PByte(Ascii), SIZE) then Halt(9);
  T := Now64;
  for R := 1 to REPS do begin St := 0; Utf8Advance(St, PByte(Ascii), SIZE); end;
  Secs := (Now64 - T) / 1e6;
  WriteLn(Format('ascii fast-path : %8.2f GB/s', [SIZE / 1073741824.0 * REPS / Secs]));

  T := Now64;
  for R := 1 to REPS do begin St := 0; Utf8AdvanceDFA(St, PByte(Ascii), SIZE); end;
  Secs := (Now64 - T) / 1e6;
  WriteLn(Format('ascii pure DFA  : %8.2f GB/s', [SIZE / 1073741824.0 * REPS / Secs]));

  T := Now64;
  for R := 1 to REPS do begin St := 0; Utf8Advance(St, PByte(Multi), SIZE); end;
  Secs := (Now64 - T) / 1e6;
  WriteLn(Format('mixed cjk/ascii : %8.2f GB/s', [SIZE / 1073741824.0 * REPS / Secs]));
end;

procedure BenchHandshake;
const
  N = 200000;
var
  Req, Resp: RawByteString;
  HS: TWSServerHandshake;
  I: Integer;
  T: Int64;
  Secs: Double;
begin
  Req := ClientBuildRequest('bench.local', '/chat', ClientGenerateKey, True);
  WriteLn('-- opening handshake (server side, deflate offered) --');
  if not ServerParseRequest(Req, True, HS) then Halt(9);
  T := Now64;
  for I := 1 to N do
  begin
    ServerParseRequest(Req, True, HS);
    Resp := ServerBuildResponse(HS);
  end;
  Secs := (Now64 - T) / 1e6;
  WriteLn(Format('parse+respond   : %8.0f k handshakes/s  (%.1f us each)',
    [N / 1e3 / Secs, Secs * 1e6 / N]));
end;

procedure BenchDeflate;
const
  REPS = 200;
var
  Msg: RawByteString;
  I: Integer;
  Defl: TWSDeflater;
  Infl: TWSInflater;
  Z: TBytes;
  T: Int64;
  Secs: Double;
begin
  Msg := '';
  for I := 1 to 16384 do
    Msg := Msg + '{"chan":"ticker","seq":' + IntToStr(I) + ',"px":101.25}' + #10;
  WriteLn('-- permessage-deflate (', Length(Msg) div 1024, ' KiB JSON-ish x ',
    REPS, ') --');

  Defl := TWSDeflater.Create(15, False);
  Infl := TWSInflater.Create(15, False, 64 * 1024 * 1024);
  try
    Defl.CompressMessage(@Msg[1], Length(Msg), Z); // warm
    T := Now64;
    for I := 1 to REPS do
      Defl.CompressMessage(@Msg[1], Length(Msg), Z);
    Secs := (Now64 - T) / 1e6;
    WriteLn(Format('compress: %8.1f MB/s in  (ratio %.1f%%)',
      [Length(Msg) / 1048576.0 * REPS / Secs, 100.0 * Length(Z) / Length(Msg)]));

    T := Now64;
    for I := 1 to REPS do
    begin
      Infl.BeginMessage;
      if not Infl.Feed(PByte(Z), Length(Z)) then Halt(9);
      if not Infl.Finish then Halt(9);
    end;
    Secs := (Now64 - T) / 1e6;
    WriteLn(Format('inflate : %8.1f MB/s out', [Length(Msg) / 1048576.0 * REPS / Secs]));
  finally
    Infl.Free;
    Defl.Free;
  end;
end;

// --- full protocol round-trip ----------------------------------------------

type
  TPipeSink = class
  public
    Hits: Int64;
    LastLen: NativeInt;
    procedure OnMsg(AText: Boolean; P: PByte; Len: NativeInt);
  end;

procedure TPipeSink.OnMsg(AText: Boolean; P: PByte; Len: NativeInt);
begin
  Inc(Hits);
  LastLen := Len;
end;

procedure Pump(Src, Dst: TWSProtocol; Scratch: TBytes);
var
  N: NativeInt;
begin
  while Src.OutPending > 0 do
  begin
    N := Src.OutPending;
    if N > Length(Scratch) then N := Length(Scratch);
    Move(Src.OutPtr^, Scratch[0], N);
    Src.OutConsume(N);
    if not Dst.Ingest(PByte(Scratch), N) then Halt(9);
  end;
end;

procedure BenchProtocol(ASize: Integer; ASecs: Double);
var
  C, S: TWSProtocol;
  CSink, SSink: TPipeSink;
  NoDeflate: TWSDeflateParams;
  Payload, Scratch: TBytes;
  I: Integer;
  T, Deadline: Int64;
  N: Int64;
  Secs: Double;
  EchoBuf: TBytes;

  procedure ServerEcho(AText: Boolean; P: PByte; Len: NativeInt);
  begin
  end;

begin
  NoDeflate.Reset;
  C := TWSProtocol.Create(wsrClient, NoDeflate);
  S := TWSProtocol.Create(wsrServer, NoDeflate);
  CSink := TPipeSink.Create;
  SSink := TPipeSink.Create;
  C.OnMessage := CSink.OnMsg;
  S.OnMessage := SSink.OnMsg;
  SetLength(Payload, ASize);
  for I := 0 to ASize - 1 do Payload[I] := Byte(I * 7);
  SetLength(Scratch, 256 * 1024);
  SetLength(EchoBuf, ASize);

  N := 0;
  T := Now64;
  Deadline := T + Round(ASecs * 1e6);
  repeat
    // client -> server
    C.SendBinary(@Payload[0], ASize);
    Pump(C, S, Scratch);
    // server echoes what it just received
    S.SendBinary(@Payload[0], ASize);
    Pump(S, C, Scratch);
    Inc(N);
  until Now64 >= Deadline;
  Secs := (Now64 - T) / 1e6;

  if (CSink.Hits <> N) or (SSink.Hits <> N) then Halt(9);
  WriteLn(Format('%7d B : %9.0f round-trips/s  %8.1f MB/s full-duplex',
    [ASize, N / Secs, 2.0 * ASize * N / 1048576.0 / Secs]));
  CSink.Free; SSink.Free; C.Free; S.Free;
end;

begin
  T0 := Now64;
  WriteLn('duetto component bench  (FPC ', {$I %FPCVERSION%}, ', ',
    {$I %FPCTARGETCPU%}, '-', {$I %FPCTARGETOS%}, ', ',
    {$ifdef PRODUCTION} 'release build' {$else} 'DEV BUILD, checks on: numbers are not representative' {$endif}, ')');
  WriteLn;
  BenchMasking; WriteLn;
  BenchFrameParse; WriteLn;
  BenchUtf8; WriteLn;
  BenchHandshake; WriteLn;
  BenchDeflate; WriteLn;
  WriteLn('-- protocol round-trip, two machines in-process, no sockets --');
  BenchProtocol(64, 1.0);
  BenchProtocol(1024, 1.0);
  BenchProtocol(16 * 1024, 1.0);
  BenchProtocol(256 * 1024, 1.0);
  WriteLn;
  WriteLn(Format('total %.1f s', [(Now64 - T0) / 1e6]));
end.
