{ WS.Utf8.Test — the DFA table in WS.Utf8 was hand-derived, not copied
  from Hoehrmann's published constants, so this suite does not trust it:
  every 1-, 2-, and 3-byte sequence (16.8M cases) is checked exhaustively
  against an independent range-rule reference validator written from the
  Unicode 15 well-formedness table (D92), plus a structured 4-byte boundary
  sweep over every lead byte with boundary continuations. The fast-path
  Utf8Advance (ASCII word scan) is asserted equivalent to the pure DFA on
  every case, and streaming state is checked across every split position. }

program WS.Utf8.Test;

{$I Shared.inc}

uses
  SysUtils,

  TestingPascalLibrary,
  WS.Utf8;

type
  TUtf8Exhaustive = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestAllOneByte;
    procedure TestAllTwoByte;
    procedure TestAllThreeByte;
    procedure TestFourByteBoundarySweep;
  end;

  TUtf8Streaming = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestStateSurvivesEverySplit;
    procedure TestRejectIsSticky;
    procedure TestMidCodePointStateIsNotAccept;
    procedure TestFastPathEqualsDFAOnMixedContent;
  end;

  TUtf8Classics = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestKnownGood;
    procedure TestKnownBad;
  end;

{ ───────── reference validator (independent of the DFA) ─────────

  Implements the Unicode 15.0 table D92 "well-formed byte sequences"
  directly as range rules. Deliberately structured nothing like the DFA so
  a shared bug is implausible. }

function RefValid(P: PByte; ALen: PtrUInt): Boolean;
var
  I: PtrUInt;
  B0: Byte;

  function Cont(AIndex: PtrUInt; ALo, AHi: Byte): Boolean;
  begin
    Result := (AIndex < ALen) and (P[AIndex] >= ALo) and (P[AIndex] <= AHi);
  end;

begin
  I := 0;
  while I < ALen do
  begin
    B0 := P[I];
    if B0 <= $7F then
      Inc(I)
    else if (B0 >= $C2) and (B0 <= $DF) then
    begin
      if not Cont(I + 1, $80, $BF) then Exit(False);
      Inc(I, 2);
    end
    else if B0 = $E0 then
    begin
      if not (Cont(I + 1, $A0, $BF) and Cont(I + 2, $80, $BF)) then Exit(False);
      Inc(I, 3);
    end
    else if ((B0 >= $E1) and (B0 <= $EC)) or (B0 = $EE) or (B0 = $EF) then
    begin
      if not (Cont(I + 1, $80, $BF) and Cont(I + 2, $80, $BF)) then Exit(False);
      Inc(I, 3);
    end
    else if B0 = $ED then
    begin
      if not (Cont(I + 1, $80, $9F) and Cont(I + 2, $80, $BF)) then Exit(False);
      Inc(I, 3);
    end
    else if B0 = $F0 then
    begin
      if not (Cont(I + 1, $90, $BF) and Cont(I + 2, $80, $BF) and
              Cont(I + 3, $80, $BF)) then Exit(False);
      Inc(I, 4);
    end
    else if (B0 >= $F1) and (B0 <= $F3) then
    begin
      if not (Cont(I + 1, $80, $BF) and Cont(I + 2, $80, $BF) and
              Cont(I + 3, $80, $BF)) then Exit(False);
      Inc(I, 4);
    end
    else if B0 = $F4 then
    begin
      if not (Cont(I + 1, $80, $8F) and Cont(I + 2, $80, $BF) and
              Cont(I + 3, $80, $BF)) then Exit(False);
      Inc(I, 4);
    end
    else
      Exit(False); // 80-C1, F5-FF can never lead
  end;
  Result := True;
end;

// Both implementations must agree with the reference; returns a count of
// disagreements so a failure names the magnitude, and records the first
// offender for the message.
function SweepAgainstReference(ABytes: PByte; ALen: PtrUInt;
  var AFirstBad: string): Boolean;
var
  Want, GotFast, GotDFA: Boolean;
  S: UInt32;
  Hex: string;
  I: PtrUInt;
begin
  Want := RefValid(ABytes, ALen);
  GotFast := Utf8Valid(ABytes, ALen);
  S := UTF8_ACCEPT;
  GotDFA := Utf8AdvanceDFA(S, ABytes, ALen) and (S = UTF8_ACCEPT);
  Result := (Want = GotFast) and (Want = GotDFA);
  if (not Result) and (AFirstBad = '') then
  begin
    Hex := '';
    for I := 0 to ALen - 1 do
      Hex := Hex + IntToHex(ABytes[I], 2) + ' ';
    AFirstBad := Format('%s-> ref=%s fast=%s dfa=%s',
      [Hex, BoolToStr(Want, True), BoolToStr(GotFast, True),
       BoolToStr(GotDFA, True)]);
  end;
end;

{ ───────── exhaustive sweeps ───────── }

procedure TUtf8Exhaustive.TestAllOneByte;
var
  B: array[0..0] of Byte;
  V: Integer;
  Bad: Integer;
  FirstBad: string;
begin
  Bad := 0;
  FirstBad := '';
  for V := 0 to 255 do
  begin
    B[0] := Byte(V);
    if not SweepAgainstReference(@B[0], 1, FirstBad) then Inc(Bad);
  end;
  Expect<string>(FirstBad).ToBe('');
  Expect<Integer>(Bad).ToBe(0);
end;

procedure TUtf8Exhaustive.TestAllTwoByte;
var
  B: array[0..1] of Byte;
  V0, V1, Bad: Integer;
  FirstBad: string;
begin
  Bad := 0;
  FirstBad := '';
  for V0 := 0 to 255 do
    for V1 := 0 to 255 do
    begin
      B[0] := Byte(V0);
      B[1] := Byte(V1);
      if not SweepAgainstReference(@B[0], 2, FirstBad) then Inc(Bad);
    end;
  Expect<string>(FirstBad).ToBe('');
  Expect<Integer>(Bad).ToBe(0);
end;

procedure TUtf8Exhaustive.TestAllThreeByte;
var
  B: array[0..2] of Byte;
  V0, V1, V2, Bad: Integer;
  FirstBad: string;
begin
  Bad := 0;
  FirstBad := '';
  for V0 := 0 to 255 do
    for V1 := 0 to 255 do
      for V2 := 0 to 255 do
      begin
        B[0] := Byte(V0);
        B[1] := Byte(V1);
        B[2] := Byte(V2);
        if not SweepAgainstReference(@B[0], 3, FirstBad) then Inc(Bad);
      end;
  Expect<string>(FirstBad).ToBe('');
  Expect<Integer>(Bad).ToBe(0);
end;

procedure TUtf8Exhaustive.TestFourByteBoundarySweep;
const
  // Every interesting continuation value: just-outside and just-inside each
  // range boundary any 4-byte rule uses, plus a mid-range value.
  Edges: array[0..8] of Byte = ($00, $7F, $80, $8F, $90, $9F, $A0, $BF, $C0);
var
  B: array[0..3] of Byte;
  L, I1, I2, I3, Bad: Integer;
  FirstBad: string;
begin
  Bad := 0;
  FirstBad := '';
  for L := $EE to $FF do // covers F0-F4 rules plus the F5-FF never-lead band
    for I1 := 0 to High(Edges) do
      for I2 := 0 to High(Edges) do
        for I3 := 0 to High(Edges) do
        begin
          B[0] := Byte(L);
          B[1] := Edges[I1];
          B[2] := Edges[I2];
          B[3] := Edges[I3];
          if not SweepAgainstReference(@B[0], 4, FirstBad) then Inc(Bad);
        end;
  Expect<string>(FirstBad).ToBe('');
  Expect<Integer>(Bad).ToBe(0);
end;

{ ───────── streaming ───────── }

procedure TUtf8Streaming.TestStateSurvivesEverySplit;
const
  // "κόσμε€𝄞" — 2-, 3-, and 4-byte code points back to back.
  S: array[0..16] of Byte = (
    $CE, $BA, $CF, $8C, $CF, $83, $CE, $BC, $CE, $B5,
    $E2, $82, $AC, $F0, $9D, $84, $9E);
var
  Split: Integer;
  St: UInt32;
  OK: Boolean;
begin
  for Split := 0 to High(S) + 1 do
  begin
    St := UTF8_ACCEPT;
    OK := Utf8Advance(St, PByte(@S[0]), Split);
    OK := OK and Utf8Advance(St, PByte(@S[0]) + Split, Length(S) - Split);
    Expect<Boolean>(OK and (St = UTF8_ACCEPT)).ToBe(True);
  end;
end;

procedure TUtf8Streaming.TestRejectIsSticky;
var
  St: UInt32;
  Bad: Byte;
  Good: Byte;
begin
  St := UTF8_ACCEPT;
  Bad := $FF;
  Good := Ord('a');
  Expect<Boolean>(Utf8Advance(St, @Bad, 1)).ToBe(False);
  Expect<Boolean>(St = UTF8_REJECT).ToBe(True);
  // Feeding more valid bytes must not resurrect the stream.
  Expect<Boolean>(Utf8Advance(St, @Good, 1)).ToBe(False);
end;

procedure TUtf8Streaming.TestMidCodePointStateIsNotAccept;
var
  St: UInt32;
  Euro: array[0..2] of Byte = ($E2, $82, $AC);
begin
  St := UTF8_ACCEPT;
  Expect<Boolean>(Utf8Advance(St, @Euro[0], 2)).ToBe(True);
  // Valid so far but a fragmented text message may not END here (§8.1):
  // the protocol layer checks State = ACCEPT on FIN, which this enables.
  Expect<Boolean>(St <> UTF8_ACCEPT).ToBe(True);
  Expect<Boolean>(St <> UTF8_REJECT).ToBe(True);
  Expect<Boolean>(Utf8Advance(St, @Euro[2], 1)).ToBe(True);
  Expect<Boolean>(St = UTF8_ACCEPT).ToBe(True);
end;

procedure TUtf8Streaming.TestFastPathEqualsDFAOnMixedContent;
var
  Buf: TBytes;
  I, Trial: Integer;
  SFast, SDFA: UInt32;
  RFast, RDFA: Boolean;
begin
  // Randomized differential: long ASCII runs (to engage the word scan)
  // interleaved with arbitrary bytes, checked byte-for-byte against the DFA.
  RandSeed := 6455;
  SetLength(Buf, 4096);
  for Trial := 1 to 200 do
  begin
    for I := 0 to High(Buf) do
      if Random(10) < 8 then
        Buf[I] := Byte(32 + Random(95)) // printable ASCII
      else
        Buf[I] := Byte(Random(256));
    SFast := UTF8_ACCEPT;
    SDFA := UTF8_ACCEPT;
    RFast := Utf8Advance(SFast, @Buf[0], Length(Buf));
    RDFA := Utf8AdvanceDFA(SDFA, @Buf[0], Length(Buf));
    Expect<Boolean>(RFast).ToBe(RDFA);
    if RFast then
      Expect<Boolean>(SFast = SDFA).ToBe(True);
  end;
end;

{ ───────── named classics ───────── }

procedure TUtf8Classics.TestKnownGood;
const
  Hello: AnsiString = 'Hello-'#$C2#$B5'@'#$C3#$9F#$C3#$B6#$C3#$A4#$C3#$BC#$C3#$A0#$C3#$A1'-UTF-8!!';
  MaxCP: array[0..3] of Byte = ($F4, $8F, $BF, $BF); // U+10FFFF
begin
  Expect<Boolean>(Utf8Valid(PByte(PAnsiChar(Hello)), Length(Hello))).ToBe(True);
  Expect<Boolean>(Utf8Valid(@MaxCP[0], 4)).ToBe(True);
  Expect<Boolean>(Utf8Valid(nil, 0)).ToBe(True); // empty text frame is valid
end;

procedure TUtf8Classics.TestKnownBad;
const
  OverlongSlash: array[0..1] of Byte = ($C0, $AF);
  OverlongNul3: array[0..2] of Byte = ($E0, $80, $80);
  Surrogate: array[0..2] of Byte = ($ED, $A0, $80);      // U+D800
  PastMax: array[0..3] of Byte = ($F4, $90, $80, $80);   // U+110000
  CESU: array[0..5] of Byte = ($ED, $A0, $BD, $ED, $B0, $80); // surrogate pair
begin
  Expect<Boolean>(Utf8Valid(@OverlongSlash[0], 2)).ToBe(False);
  Expect<Boolean>(Utf8Valid(@OverlongNul3[0], 3)).ToBe(False);
  Expect<Boolean>(Utf8Valid(@Surrogate[0], 3)).ToBe(False);
  Expect<Boolean>(Utf8Valid(@PastMax[0], 4)).ToBe(False);
  Expect<Boolean>(Utf8Valid(@CESU[0], 6)).ToBe(False);
end;

procedure TUtf8Exhaustive.SetupTests;
begin
  Test('every 1-byte sequence matches reference',  TestAllOneByte);
  Test('every 2-byte sequence matches reference',  TestAllTwoByte);
  Test('every 3-byte sequence matches reference',  TestAllThreeByte);
  Test('4-byte lead x boundary continuations',     TestFourByteBoundarySweep);
end;

procedure TUtf8Streaming.SetupTests;
begin
  Test('state survives every split position',      TestStateSurvivesEverySplit);
  Test('REJECT is sticky',                         TestRejectIsSticky);
  Test('mid-code-point state is not ACCEPT',       TestMidCodePointStateIsNotAccept);
  Test('fast path equals DFA on mixed content',    TestFastPathEqualsDFAOnMixedContent);
end;

procedure TUtf8Classics.SetupTests;
begin
  Test('known-good corpus',                        TestKnownGood);
  Test('overlongs, surrogates, out-of-range',      TestKnownBad);
end;

begin
  TestRunnerProgram.AddSuite(TUtf8Exhaustive.Create('UTF-8: exhaustive vs reference'));
  TestRunnerProgram.AddSuite(TUtf8Streaming.Create('UTF-8: streaming'));
  TestRunnerProgram.AddSuite(TUtf8Classics.Create('UTF-8: classics'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
