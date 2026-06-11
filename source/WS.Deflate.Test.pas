{ WS.Deflate.Test — RFC 7692 round trips (empty message, text, 100 KB
  random, 1 MB zeros), the §7.2.3.6 empty-message-becomes-#$00 rule,
  context takeover semantics observable from the wire (a repeated message
  compresses smaller when the window is shared, and does not when
  no_context_takeover resets it), the decompression-bomb output cap, and
  corrupt-stream rejection. }

program WS.Deflate.Test;

{$I Shared.inc}

uses
  SysUtils,

  TestingPascalLibrary,
  WS.Deflate;

type
  TDeflateRoundTrip = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestEmptyMessage;
    procedure TestText;
    procedure TestRandom100K;
    procedure TestZeros1M;
    procedure TestChunkedFeed;
  end;

  TDeflateTakeover = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestSharedWindowShrinksRepeats;
    procedure TestNoTakeoverDoesNot;
  end;

  TDeflateDefence = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestBombCap;
    procedure TestCorruptStream;
  end;

function RoundTrip(C: TWSDeflater; D: TWSInflater;
  const AIn: TBytes; out AOut: TBytes): Boolean;
var
  Z: TBytes;
  P: PByte;
begin
  Result := False;
  if Length(AIn) > 0 then P := @AIn[0] else P := nil;
  if not C.CompressMessage(P, Length(AIn), Z) then Exit;
  D.BeginMessage;
  if not D.Feed(@Z[0], Length(Z)) then Exit;
  if not D.Finish then Exit;
  SetLength(AOut, D.OutSize);
  if D.OutSize > 0 then
    Move(D.OutData[0], AOut[0], D.OutSize);
  Result := True;
end;

function SameBytes(const A, B: TBytes): Boolean;
begin
  Result := (Length(A) = Length(B)) and
    ((Length(A) = 0) or CompareMem(@A[0], @B[0], Length(A)));
end;

{ ───────── round trips ───────── }

procedure TDeflateRoundTrip.TestEmptyMessage;
var
  C: TWSDeflater;
  D: TWSInflater;
  Z, OutB: TBytes;
begin
  C := TWSDeflater.Create(15, False);
  D := TWSInflater.Create(15, False, 1 shl 20);
  try
    Expect<Boolean>(C.CompressMessage(nil, 0, Z)).ToBe(True);
    // §7.2.3.6: an empty uncompressed payload becomes the single byte 00.
    Expect<Integer>(Length(Z)).ToBe(1);
    Expect<Integer>(Z[0]).ToBe($00);
    D.BeginMessage;
    Expect<Boolean>(D.Feed(@Z[0], 1)).ToBe(True);
    Expect<Boolean>(D.Finish).ToBe(True);
    Expect<Integer>(Integer(D.OutSize)).ToBe(0);
    SetLength(OutB, 0);
  finally
    C.Free;
    D.Free;
  end;
end;

procedure TDeflateRoundTrip.TestText;
var
  C: TWSDeflater;
  D: TWSInflater;
  InB, OutB: TBytes;
  S: AnsiString;
begin
  S := 'Hello, RFC 7692! Hello, RFC 7692! Hello, RFC 7692!';
  SetLength(InB, Length(S));
  Move(S[1], InB[0], Length(S));
  C := TWSDeflater.Create(15, False);
  D := TWSInflater.Create(15, False, 1 shl 20);
  try
    Expect<Boolean>(RoundTrip(C, D, InB, OutB)).ToBe(True);
    Expect<Boolean>(SameBytes(InB, OutB)).ToBe(True);
  finally
    C.Free;
    D.Free;
  end;
end;

procedure TDeflateRoundTrip.TestRandom100K;
var
  C: TWSDeflater;
  D: TWSInflater;
  InB, OutB: TBytes;
  I: Integer;
begin
  RandSeed := 7692;
  SetLength(InB, 100 * 1024);
  for I := 0 to High(InB) do InB[I] := Byte(Random(256));
  C := TWSDeflater.Create(15, False);
  D := TWSInflater.Create(15, False, 4 shl 20);
  try
    Expect<Boolean>(RoundTrip(C, D, InB, OutB)).ToBe(True);
    Expect<Boolean>(SameBytes(InB, OutB)).ToBe(True);
  finally
    C.Free;
    D.Free;
  end;
end;

procedure TDeflateRoundTrip.TestZeros1M;
var
  C: TWSDeflater;
  D: TWSInflater;
  InB, OutB, Z: TBytes;
begin
  SetLength(InB, 1 shl 20);
  FillChar(InB[0], Length(InB), 0);
  C := TWSDeflater.Create(15, False);
  D := TWSInflater.Create(15, False, 2 shl 20);
  try
    Expect<Boolean>(C.CompressMessage(@InB[0], Length(InB), Z)).ToBe(True);
    // 1 MB of zeros must compress to a few KB — sanity-check the ratio.
    Expect<Boolean>(Length(Z) < 8192).ToBe(True);
    D.BeginMessage;
    Expect<Boolean>(D.Feed(@Z[0], Length(Z))).ToBe(True);
    Expect<Boolean>(D.Finish).ToBe(True);
    SetLength(OutB, D.OutSize);
    Move(D.OutData[0], OutB[0], D.OutSize);
    Expect<Boolean>(SameBytes(InB, OutB)).ToBe(True);
  finally
    C.Free;
    D.Free;
  end;
end;

procedure TDeflateRoundTrip.TestChunkedFeed;
var
  C: TWSDeflater;
  D: TWSInflater;
  InB, Z, OutB: TBytes;
  I, Cut: Integer;
  S: AnsiString;
begin
  // A compressed message arriving as several fragments: Feed is called per
  // chunk, Finish once. Every split position of the compressed bytes.
  S := 'fragmented compressed payload, fragmented compressed payload';
  SetLength(InB, Length(S));
  Move(S[1], InB[0], Length(S));
  C := TWSDeflater.Create(15, False);
  try
    Expect<Boolean>(C.CompressMessage(@InB[0], Length(InB), Z)).ToBe(True);
    for Cut := 0 to Length(Z) do
    begin
      D := TWSInflater.Create(15, False, 1 shl 20);
      try
        D.BeginMessage;
        Expect<Boolean>(D.Feed(@Z[0], Cut)).ToBe(True);
        Expect<Boolean>(D.Feed(PByte(@Z[0]) + Cut, Length(Z) - Cut)).ToBe(True);
        Expect<Boolean>(D.Finish).ToBe(True);
        SetLength(OutB, D.OutSize);
        if D.OutSize > 0 then Move(D.OutData[0], OutB[0], D.OutSize);
        Expect<Boolean>(SameBytes(InB, OutB)).ToBe(True);
      finally
        D.Free;
      end;
    end;
  finally
    C.Free;
  end;
  I := 0; // silence unused in case the loop folds
  if I <> 0 then;
end;

{ ───────── context takeover ───────── }

procedure TDeflateTakeover.TestSharedWindowShrinksRepeats;
var
  C: TWSDeflater;
  InB, Z1, Z2: TBytes;
  I: Integer;
begin
  RandSeed := 42;
  SetLength(InB, 4096);
  for I := 0 to High(InB) do InB[I] := Byte(Random(256));
  C := TWSDeflater.Create(15, False); // takeover: window survives messages
  try
    Expect<Boolean>(C.CompressMessage(@InB[0], Length(InB), Z1)).ToBe(True);
    Expect<Boolean>(C.CompressMessage(@InB[0], Length(InB), Z2)).ToBe(True);
    // Second identical message references the window: dramatically smaller.
    Expect<Boolean>(Length(Z2) * 4 < Length(Z1)).ToBe(True);
  finally
    C.Free;
  end;
end;

procedure TDeflateTakeover.TestNoTakeoverDoesNot;
var
  C: TWSDeflater;
  D: TWSInflater;
  InB, Z1, Z2, OutB: TBytes;
  I: Integer;
begin
  RandSeed := 42;
  SetLength(InB, 4096);
  for I := 0 to High(InB) do InB[I] := Byte(Random(256));
  C := TWSDeflater.Create(15, True); // no_context_takeover
  D := TWSInflater.Create(15, True, 1 shl 20);
  try
    Expect<Boolean>(C.CompressMessage(@InB[0], Length(InB), Z1)).ToBe(True);
    Expect<Boolean>(C.CompressMessage(@InB[0], Length(InB), Z2)).ToBe(True);
    // Window reset between messages: no cross-message references, so the
    // repeat cannot collapse (random data: compressed size stays ~input).
    Expect<Boolean>(Length(Z2) > Length(InB) div 2).ToBe(True);
    // And each message must decode independently on a resetting inflater.
    Expect<Boolean>(RoundTrip(C, D, InB, OutB)).ToBe(True);
    Expect<Boolean>(SameBytes(InB, OutB)).ToBe(True);
    Expect<Boolean>(RoundTrip(C, D, InB, OutB)).ToBe(True);
    Expect<Boolean>(SameBytes(InB, OutB)).ToBe(True);
  finally
    C.Free;
    D.Free;
  end;
end;

{ ───────── defence ───────── }

procedure TDeflateDefence.TestBombCap;
var
  C: TWSDeflater;
  D: TWSInflater;
  InB, Z: TBytes;
  OK: Boolean;
begin
  // 16 MB of zeros compresses to ~16 KB; cap output at 64 KB and the
  // inflater must refuse rather than balloon.
  SetLength(InB, 16 shl 20);
  FillChar(InB[0], Length(InB), 0);
  C := TWSDeflater.Create(15, False);
  D := TWSInflater.Create(15, False, 64 * 1024);
  try
    Expect<Boolean>(C.CompressMessage(@InB[0], Length(InB), Z)).ToBe(True);
    Expect<Boolean>(Length(Z) < 64 * 1024).ToBe(True); // the bomb is small
    D.BeginMessage;
    OK := D.Feed(@Z[0], Length(Z)) and D.Finish;
    Expect<Boolean>(OK).ToBe(False);
  finally
    C.Free;
    D.Free;
  end;
end;

procedure TDeflateDefence.TestCorruptStream;
var
  D: TWSInflater;
  Junk: array[0..15] of Byte;
  I: Integer;
  OK: Boolean;
begin
  for I := 0 to High(Junk) do Junk[I] := $A5;
  D := TWSInflater.Create(15, False, 1 shl 20);
  try
    D.BeginMessage;
    OK := D.Feed(@Junk[0], Length(Junk)) and D.Finish;
    Expect<Boolean>(OK).ToBe(False);
  finally
    D.Free;
  end;
end;

procedure TDeflateRoundTrip.SetupTests;
begin
  Test('empty message is #$00 and round-trips',  TestEmptyMessage);
  Test('text round trip',                        TestText);
  Test('100 KB random round trip',               TestRandom100K);
  Test('1 MB zeros round trip + ratio sanity',   TestZeros1M);
  Test('chunked Feed at every split',            TestChunkedFeed);
end;

procedure TDeflateTakeover.SetupTests;
begin
  Test('shared window shrinks repeats',          TestSharedWindowShrinksRepeats);
  Test('no_context_takeover resets window',      TestNoTakeoverDoesNot);
end;

procedure TDeflateDefence.SetupTests;
begin
  Test('decompression bomb hits output cap',     TestBombCap);
  Test('corrupt stream rejected',                TestCorruptStream);
end;

begin
  TestRunnerProgram.AddSuite(TDeflateRoundTrip.Create('Deflate: round trips'));
  TestRunnerProgram.AddSuite(TDeflateTakeover.Create('Deflate: context takeover'));
  TestRunnerProgram.AddSuite(TDeflateDefence.Create('Deflate: defence'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
