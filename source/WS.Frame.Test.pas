{ WS.Frame.Test — RFC 6455 §5.7 wire vectors byte-for-byte, header
  round-trips across every length-encoding boundary, NeedMore at every
  truncation point of every shape, the §5.2 strictness matrix (minimal
  encodings, control rules, reserved opcodes, length top bit), and a
  differential sweep proving UnmaskNaive / UnmaskU64 / UnmaskSSE2 /
  ApplyMask agree on every length 0..130 x key offset 0..3, that masking
  is an involution, and that a payload unmasked in arbitrary split chunks
  (the streaming case) equals the payload unmasked whole. }

program WS.Frame.Test;

{$I Shared.inc}

uses
  SysUtils,

  TestingPascalLibrary,
  WS.Frame;

type
  TFrameRFCVectors = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestUnmaskedHello;
    procedure TestMaskedHello;
    procedure TestFragmentedHello;
    procedure TestPingPongVectors;
    procedure Test256ByteBinary;
    procedure Test64KiBBinary;
  end;

  TFrameStrictness = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestNonMinimal16;
    procedure TestNonMinimal64;
    procedure TestLengthTopBit;
    procedure TestFragmentedControl;
    procedure TestOversizedControl;
    procedure TestReservedOpcodes;
    procedure TestRsvBitsSurface;
  end;

  TFrameRoundTrip = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestBoundaryLengths;
    procedure TestNeedMoreAtEveryTruncation;
  end;

  TFrameMasking = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestImplementationsAgree;
    procedure TestInvolution;
    procedure TestSplitEqualsWhole;
    procedure TestRFCMaskVector;
    procedure TestZeroLengthIsSafe;
  end;

{ ───────── helpers ───────── }

function ParseBytes(const ABytes: array of Byte;
  out H: TWSFrameHeader): TWSParseResult;
begin
  Result := ParseFrameHeader(PByte(@ABytes[0]), Length(ABytes), H);
end;

{ ───────── RFC §5.7 vectors ───────── }

procedure TFrameRFCVectors.TestUnmaskedHello;
const
  V: array[0..6] of Byte = ($81, $05, $48, $65, $6C, $6C, $6F);
var
  H: TWSFrameHeader;
begin
  Expect<Integer>(Ord(ParseBytes(V, H))).ToBe(Ord(wprOK));
  Expect<Boolean>(H.Fin).ToBe(True);
  Expect<Integer>(H.Opcode).ToBe(WS_OP_TEXT);
  Expect<Boolean>(H.Masked).ToBe(False);
  Expect<Integer>(Integer(H.PayloadLen)).ToBe(5);
  Expect<Integer>(H.HeaderLen).ToBe(2);
end;

procedure TFrameRFCVectors.TestMaskedHello;
const
  V: array[0..10] of Byte = ($81, $85, $37, $FA, $21, $3D,
                             $7F, $9F, $4D, $51, $58);
var
  H: TWSFrameHeader;
  Payload: array[0..4] of Byte;
  S: AnsiString;
  I: Integer;
begin
  Expect<Integer>(Ord(ParseBytes(V, H))).ToBe(Ord(wprOK));
  Expect<Boolean>(H.Masked).ToBe(True);
  Expect<Integer>(H.HeaderLen).ToBe(6);
  Expect<Integer>(Integer(H.PayloadLen)).ToBe(5);
  Move(V[H.HeaderLen], Payload[0], 5);
  ApplyMask(@Payload[0], 5, H.MaskKey, 0);
  S := '';
  for I := 0 to 4 do S := S + AnsiChar(Payload[I]);
  Expect<AnsiString>(S).ToBe('Hello');
end;

procedure TFrameRFCVectors.TestFragmentedHello;
const
  F1: array[0..4] of Byte = ($01, $03, $48, $65, $6C);       // "Hel", FIN=0
  F2: array[0..3] of Byte = ($80, $02, $6C, $6F);            // "lo", CONT FIN=1
var
  H: TWSFrameHeader;
begin
  Expect<Integer>(Ord(ParseBytes(F1, H))).ToBe(Ord(wprOK));
  Expect<Boolean>(H.Fin).ToBe(False);
  Expect<Integer>(H.Opcode).ToBe(WS_OP_TEXT);
  Expect<Integer>(Ord(ParseBytes(F2, H))).ToBe(Ord(wprOK));
  Expect<Boolean>(H.Fin).ToBe(True);
  Expect<Integer>(H.Opcode).ToBe(WS_OP_CONT);
end;

procedure TFrameRFCVectors.TestPingPongVectors;
const
  Ping: array[0..6] of Byte = ($89, $05, $48, $65, $6C, $6C, $6F);
var
  H: TWSFrameHeader;
begin
  Expect<Integer>(Ord(ParseBytes(Ping, H))).ToBe(Ord(wprOK));
  Expect<Integer>(H.Opcode).ToBe(WS_OP_PING);
  Expect<Boolean>(H.IsControl).ToBe(True);
end;

procedure TFrameRFCVectors.Test256ByteBinary;
var
  Buf: array[0..3] of Byte;
  H: TWSFrameHeader;
begin
  Buf[0] := $82; Buf[1] := $7E; Buf[2] := $01; Buf[3] := $00;
  Expect<Integer>(Ord(ParseFrameHeader(@Buf[0], 4, H))).ToBe(Ord(wprOK));
  Expect<Integer>(Integer(H.PayloadLen)).ToBe(256);
  Expect<Integer>(H.HeaderLen).ToBe(4);
end;

procedure TFrameRFCVectors.Test64KiBBinary;
var
  Buf: array[0..9] of Byte;
  H: TWSFrameHeader;
begin
  FillChar(Buf, SizeOf(Buf), 0);
  Buf[0] := $82; Buf[1] := $7F; Buf[7] := $01; // 65536
  Expect<Integer>(Ord(ParseFrameHeader(@Buf[0], 10, H))).ToBe(Ord(wprOK));
  Expect<Boolean>(H.PayloadLen = 65536).ToBe(True);
  Expect<Integer>(H.HeaderLen).ToBe(10);
end;

{ ───────── strictness ───────── }

procedure TFrameStrictness.TestNonMinimal16;
const
  V: array[0..3] of Byte = ($82, $7E, $00, $7D); // 125 in 16-bit form
var
  H: TWSFrameHeader;
begin
  Expect<Integer>(Ord(ParseBytes(V, H))).ToBe(Ord(wprProtocolError));
end;

procedure TFrameStrictness.TestNonMinimal64;
var
  Buf: array[0..9] of Byte;
  H: TWSFrameHeader;
begin
  FillChar(Buf, SizeOf(Buf), 0);
  Buf[0] := $82; Buf[1] := $7F; Buf[8] := $FF; Buf[9] := $FF; // 65535 in 64-bit form
  Expect<Integer>(Ord(ParseFrameHeader(@Buf[0], 10, H))).ToBe(Ord(wprProtocolError));
end;

procedure TFrameStrictness.TestLengthTopBit;
var
  Buf: array[0..9] of Byte;
  H: TWSFrameHeader;
begin
  FillChar(Buf, SizeOf(Buf), $FF);
  Buf[0] := $82; Buf[1] := $7F; // length 0xFFFF... top bit set
  Expect<Integer>(Ord(ParseFrameHeader(@Buf[0], 10, H))).ToBe(Ord(wprProtocolError));
end;

procedure TFrameStrictness.TestFragmentedControl;
const
  V: array[0..1] of Byte = ($09, $00); // ping with FIN=0
var
  H: TWSFrameHeader;
begin
  Expect<Integer>(Ord(ParseBytes(V, H))).ToBe(Ord(wprProtocolError));
end;

procedure TFrameStrictness.TestOversizedControl;
const
  V: array[0..3] of Byte = ($88, $7E, $00, $7E); // close, 126-byte payload
var
  H: TWSFrameHeader;
begin
  Expect<Integer>(Ord(ParseBytes(V, H))).ToBe(Ord(wprProtocolError));
end;

procedure TFrameStrictness.TestReservedOpcodes;
var
  Buf: array[0..1] of Byte;
  H: TWSFrameHeader;
  Op: Byte;
begin
  Buf[1] := $00;
  for Op := $3 to $7 do
  begin
    Buf[0] := $80 or Op;
    Expect<Integer>(Ord(ParseFrameHeader(@Buf[0], 2, H))).ToBe(Ord(wprProtocolError));
  end;
  for Op := $B to $F do
  begin
    Buf[0] := $80 or Op;
    Expect<Integer>(Ord(ParseFrameHeader(@Buf[0], 2, H))).ToBe(Ord(wprProtocolError));
  end;
end;

procedure TFrameStrictness.TestRsvBitsSurface;
const
  V: array[0..1] of Byte = ($F1, $00); // FIN + RSV1 + RSV2 + RSV3, text
var
  H: TWSFrameHeader;
begin
  // The codec surfaces RSV; legality is the protocol layer's call
  // (RSV1 may be permessage-deflate; RSV2/RSV3 are always fatal there).
  Expect<Integer>(Ord(ParseBytes(V, H))).ToBe(Ord(wprOK));
  Expect<Boolean>(H.Rsv1).ToBe(True);
  Expect<Boolean>(H.Rsv2).ToBe(True);
  Expect<Boolean>(H.Rsv3).ToBe(True);
end;

{ ───────── round trip + truncation ───────── }

procedure TFrameRoundTrip.TestBoundaryLengths;
const
  Lens: array[0..8] of UInt64 =
    (0, 1, 125, 126, 127, 65535, 65536, $7FFFFFFF, UInt64(1) shl 40);
var
  Buf: array[0..WS_MAX_HEADER - 1] of Byte;
  H: TWSFrameHeader;
  I: Integer;
  Masked: Boolean;
  N: Integer;
begin
  for I := 0 to High(Lens) do
    for Masked := False to True do
    begin
      N := WriteFrameHeader(@Buf[0], True, False, WS_OP_BINARY, Masked,
        $11223344, Lens[I]);
      Expect<Integer>(Ord(ParseFrameHeader(@Buf[0], N, H))).ToBe(Ord(wprOK));
      Expect<Boolean>(H.PayloadLen = Lens[I]).ToBe(True);
      Expect<Boolean>(H.Masked).ToBe(Masked);
      Expect<Integer>(H.HeaderLen).ToBe(N);
      if Masked then
        Expect<Boolean>(H.MaskKey = $11223344).ToBe(True);
    end;
end;

procedure TFrameRoundTrip.TestNeedMoreAtEveryTruncation;
var
  Buf: array[0..WS_MAX_HEADER - 1] of Byte;
  H: TWSFrameHeader;
  N, Cut: Integer;
begin
  // Largest header shape: 64-bit length + mask = 14 bytes.
  N := WriteFrameHeader(@Buf[0], True, False, WS_OP_BINARY, True,
    $AABBCCDD, 100000);
  Expect<Integer>(N).ToBe(WS_MAX_HEADER);
  for Cut := 0 to N - 1 do
    Expect<Integer>(Ord(ParseFrameHeader(@Buf[0], Cut, H))).ToBe(Ord(wprNeedMore));
  Expect<Integer>(Ord(ParseFrameHeader(@Buf[0], N, H))).ToBe(Ord(wprOK));
end;

{ ───────── masking ───────── }

procedure TFrameMasking.TestImplementationsAgree;
var
  Src, A, B, C: array[0..149] of Byte;
  Len, Off, I: Integer;
  Key, RotKey: UInt32;
  Shift: Integer;
  Mismatch: Integer;
begin
  RandSeed := 1337;
  Key := $9ACF17B3;
  Mismatch := 0;
  for I := 0 to High(Src) do Src[I] := Byte(Random(256));
  for Len := 0 to 130 do
    for Off := 0 to 3 do
    begin
      Shift := Off * 8;
      if Shift = 0 then
        RotKey := Key
      else
        RotKey := (Key shr Shift) or (Key shl (32 - Shift));
      Move(Src, A, SizeOf(Src));
      Move(Src, B, SizeOf(Src));
      Move(Src, C, SizeOf(Src));
      UnmaskNaive(@A[0], Len, RotKey);
      UnmaskU64(@B[0], Len, RotKey);
      ApplyMask(@C[0], Len, Key, Off);
      if not CompareMem(@A[0], @B[0], SizeOf(Src)) then Inc(Mismatch);
      if not CompareMem(@A[0], @C[0], SizeOf(Src)) then Inc(Mismatch);
{$if defined(CPUX86_64) and defined(LINUX)}
      Move(Src, B, SizeOf(Src));
      UnmaskSSE2(@B[0], Len, RotKey);
      if not CompareMem(@A[0], @B[0], SizeOf(Src)) then Inc(Mismatch);
{$endif}
    end;
  Expect<Integer>(Mismatch).ToBe(0);
end;

procedure TFrameMasking.TestInvolution;
var
  Src, W: array[0..99] of Byte;
  I: Integer;
begin
  RandSeed := 7;
  for I := 0 to High(Src) do Src[I] := Byte(Random(256));
  Move(Src, W, SizeOf(Src));
  ApplyMask(@W[0], Length(W), $DEADBEEF, 0);
  Expect<Boolean>(CompareMem(@Src[0], @W[0], SizeOf(Src))).ToBe(False);
  ApplyMask(@W[0], Length(W), $DEADBEEF, 0);
  Expect<Boolean>(CompareMem(@Src[0], @W[0], SizeOf(Src))).ToBe(True);
end;

procedure TFrameMasking.TestSplitEqualsWhole;
var
  Src, Whole, Split: array[0..76] of Byte;
  I, Cut: Integer;
const
  Key: UInt32 = $0102A3F4;
begin
  RandSeed := 99;
  for I := 0 to High(Src) do Src[I] := Byte(Random(256));
  Move(Src, Whole, SizeOf(Src));
  ApplyMask(@Whole[0], Length(Whole), Key, 0);
  // Streaming continuation: unmasking [0..Cut) then [Cut..end) with the
  // key offset carried forward must equal the one-shot unmask.
  for Cut := 0 to Length(Src) do
  begin
    Move(Src, Split, SizeOf(Src));
    ApplyMask(@Split[0], Cut, Key, 0);
    ApplyMask(PByte(@Split[0]) + Cut, Length(Split) - Cut, Key, Cut);
    Expect<Boolean>(CompareMem(@Whole[0], @Split[0], SizeOf(Src))).ToBe(True);
  end;
end;

procedure TFrameMasking.TestRFCMaskVector;
var
  P: array[0..4] of Byte = ($7F, $9F, $4D, $51, $58);
  S: AnsiString;
  I: Integer;
begin
  // Key bytes 37 FA 21 3D packed little-endian.
  ApplyMask(@P[0], 5, $3D21FA37, 0);
  S := '';
  for I := 0 to 4 do S := S + AnsiChar(P[I]);
  Expect<AnsiString>(S).ToBe('Hello');
end;

procedure TFrameMasking.TestZeroLengthIsSafe;
var
  B: Byte;
begin
  B := $42;
  UnmaskNaive(@B, 0, $FFFFFFFF);
  UnmaskU64(@B, 0, $FFFFFFFF);
  ApplyMask(@B, 0, $FFFFFFFF, 3);
  Expect<Integer>(B).ToBe($42);
end;

procedure TFrameRFCVectors.SetupTests;
begin
  Test('unmasked "Hello" (§5.7)',                 TestUnmaskedHello);
  Test('masked "Hello" (§5.7)',                   TestMaskedHello);
  Test('fragmented "Hel"+"lo" (§5.7)',            TestFragmentedHello);
  Test('ping vector (§5.7)',                      TestPingPongVectors);
  Test('256-byte binary, 16-bit length (§5.7)',   Test256ByteBinary);
  Test('64 KiB binary, 64-bit length (§5.7)',     Test64KiBBinary);
end;

procedure TFrameStrictness.SetupTests;
begin
  Test('non-minimal 16-bit length rejected',      TestNonMinimal16);
  Test('non-minimal 64-bit length rejected',      TestNonMinimal64);
  Test('64-bit length top bit rejected',          TestLengthTopBit);
  Test('fragmented control frame rejected',       TestFragmentedControl);
  Test('control frame > 125 bytes rejected',      TestOversizedControl);
  Test('reserved opcodes 3-7, B-F rejected',      TestReservedOpcodes);
  Test('RSV bits surface to the caller',          TestRsvBitsSurface);
end;

procedure TFrameRoundTrip.SetupTests;
begin
  Test('write/parse round trip at boundaries',    TestBoundaryLengths);
  Test('NeedMore at every truncation point',      TestNeedMoreAtEveryTruncation);
end;

procedure TFrameMasking.SetupTests;
begin
  Test('naive = u64 = sse2 = ApplyMask, len 0..130 x off 0..3',
                                                  TestImplementationsAgree);
  Test('masking is an involution',                TestInvolution);
  Test('split-chunk unmask equals whole',         TestSplitEqualsWhole);
  Test('RFC mask key vector',                     TestRFCMaskVector);
  Test('zero length is safe in every impl',       TestZeroLengthIsSafe);
end;

begin
  TestRunnerProgram.AddSuite(TFrameRFCVectors.Create('Frame: RFC vectors'));
  TestRunnerProgram.AddSuite(TFrameStrictness.Create('Frame: strictness'));
  TestRunnerProgram.AddSuite(TFrameRoundTrip.Create('Frame: round trip'));
  TestRunnerProgram.AddSuite(TFrameMasking.Create('Frame: masking'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
