unit WS.Frame;

// RFC 6455 §5 — framing. Pure codec, no I/O, no allocation on the parse
// path: ParseHeader reads a header out of a caller-owned buffer and the
// payload stays where it is. Masking is in-place.
//
// Strictness (server role relies on this; Autobahn-grade):
//   - RSV bits surface to the caller; the protocol layer decides whether
//     RSV1 is legal (permessage-deflate) — RSV2/RSV3 are always fatal.
//   - Control frames: FIN required, payload <= 125.
//   - Length encodings must be minimal (126-form requires >= 126,
//     127-form requires >= 65536, top bit of 64-bit length must be 0).

{$I Shared.inc}
{$ifdef CPUX86_64}{$asmmode intel}{$endif}

interface

const
  // Opcodes (§5.2)
  WS_OP_CONT   = $0;
  WS_OP_TEXT   = $1;
  WS_OP_BINARY = $2;
  WS_OP_CLOSE  = $8;
  WS_OP_PING   = $9;
  WS_OP_PONG   = $A;

  WS_MAX_HEADER = 14; // 2 + 8 (ext len) + 4 (mask)

type
  TWSParseResult = (wprOK, wprNeedMore, wprProtocolError);

  TWSFrameHeader = record
    Fin: Boolean;
    Rsv1, Rsv2, Rsv3: Boolean;
    Opcode: Byte;
    Masked: Boolean;
    MaskKey: UInt32;       // wire-order bytes packed little-endian (byte 0 = lowest)
    PayloadLen: UInt64;
    HeaderLen: Integer;    // bytes consumed by the header itself
    function IsControl: Boolean; inline;
  end;

// Parse a frame header from Buf[0..Len-1]. On wprOK, Header is filled and
// the payload begins at Buf + Header.HeaderLen. Never reads past Len.
function ParseFrameHeader(ABuf: PByte; ALen: PtrUInt;
  out AHeader: TWSFrameHeader): TWSParseResult;

// Serialize a header into Buf (must hold WS_MAX_HEADER bytes). Returns
// header length. Mask key bytes are emitted in wire order when AMasked.
function WriteFrameHeader(ABuf: PByte; AFin: Boolean; ARsv1: Boolean;
  AOpcode: Byte; AMasked: Boolean; AMaskKey: UInt32;
  APayloadLen: UInt64): Integer;

// XOR Len bytes at P with the 4-byte mask key, starting at key offset
// AKeyOffset (mod 4) — offset support is what makes streaming unmask of a
// payload split across TCP reads possible. Dispatches to the fastest
// available implementation.
procedure ApplyMask(P: PByte; ALen: PtrUInt; AKey: UInt32; AKeyOffset: PtrUInt);

// Individual implementations, exported so wsbench can race them and the
// tests can assert equivalence.
procedure UnmaskNaive(P: PByte; ALen: PtrUInt; ARotKey: UInt32);
procedure UnmaskU64(P: PByte; ALen: PtrUInt; ARotKey: UInt32);
{$if defined(CPUX86_64) and defined(LINUX)}
procedure UnmaskSSE2(P: PByte; ALen: PtrUInt; ARotKey: UInt32);
{$endif}

implementation

function TWSFrameHeader.IsControl: Boolean;
begin
  Result := (Opcode and $8) <> 0;
end;

function ParseFrameHeader(ABuf: PByte; ALen: PtrUInt;
  out AHeader: TWSFrameHeader): TWSParseResult;
var
  B0, B1, LenByte: Byte;
  Need: PtrUInt;
  L: UInt64;
begin
  Result := wprNeedMore;
  if ALen < 2 then Exit;

  B0 := ABuf[0];
  B1 := ABuf[1];

  AHeader.Fin    := (B0 and $80) <> 0;
  AHeader.Rsv1   := (B0 and $40) <> 0;
  AHeader.Rsv2   := (B0 and $20) <> 0;
  AHeader.Rsv3   := (B0 and $10) <> 0;
  AHeader.Opcode := B0 and $0F;
  AHeader.Masked := (B1 and $80) <> 0;
  LenByte       := B1 and $7F;

  // Reserved opcodes (§5.2): 3-7 and B-F are fail-the-connection.
  case AHeader.Opcode of
    WS_OP_CONT, WS_OP_TEXT, WS_OP_BINARY,
    WS_OP_CLOSE, WS_OP_PING, WS_OP_PONG:;
  else
    Exit(wprProtocolError);
  end;

  // Control frames must not be fragmented and carry <= 125 bytes (§5.5).
  if AHeader.IsControl then
    if (not AHeader.Fin) or (LenByte > 125) then
      Exit(wprProtocolError);

  Need := 2;
  case LenByte of
    126: Inc(Need, 2);
    127: Inc(Need, 8);
  end;
  if AHeader.Masked then Inc(Need, 4);
  if ALen < Need then Exit; // wprNeedMore

  case LenByte of
    126:
      begin
        L := (UInt64(ABuf[2]) shl 8) or ABuf[3];
        if L < 126 then Exit(wprProtocolError); // minimal encoding (§5.2)
      end;
    127:
      begin
        L := (UInt64(ABuf[2]) shl 56) or (UInt64(ABuf[3]) shl 48) or
             (UInt64(ABuf[4]) shl 40) or (UInt64(ABuf[5]) shl 32) or
             (UInt64(ABuf[6]) shl 24) or (UInt64(ABuf[7]) shl 16) or
             (UInt64(ABuf[8]) shl 8)  or  UInt64(ABuf[9]);
        if (L and (UInt64(1) shl 63)) <> 0 then Exit(wprProtocolError);
        if L < 65536 then Exit(wprProtocolError); // minimal encoding
      end;
  else
    L := LenByte;
  end;
  AHeader.PayloadLen := L;

  if AHeader.Masked then
  begin
    // Pack wire-order bytes little-endian: data byte i XORs key byte i mod 4,
    // which is exactly bits 8*(i mod 4) of this UInt32.
    AHeader.MaskKey :=
      UInt32(ABuf[Need - 4]) or (UInt32(ABuf[Need - 3]) shl 8) or
      (UInt32(ABuf[Need - 2]) shl 16) or (UInt32(ABuf[Need - 1]) shl 24);
  end
  else
    AHeader.MaskKey := 0;

  AHeader.HeaderLen := Integer(Need);
  Result := wprOK;
end;

function WriteFrameHeader(ABuf: PByte; AFin: Boolean; ARsv1: Boolean;
  AOpcode: Byte; AMasked: Boolean; AMaskKey: UInt32;
  APayloadLen: UInt64): Integer;
var
  N: Integer;
begin
  ABuf[0] := AOpcode and $0F;
  if AFin then ABuf[0] := ABuf[0] or $80;
  if ARsv1 then ABuf[0] := ABuf[0] or $40;

  if APayloadLen < 126 then
  begin
    ABuf[1] := Byte(APayloadLen);
    N := 2;
  end
  else if APayloadLen < 65536 then
  begin
    ABuf[1] := 126;
    ABuf[2] := Byte(APayloadLen shr 8);
    ABuf[3] := Byte(APayloadLen);
    N := 4;
  end
  else
  begin
    ABuf[1] := 127;
    ABuf[2] := Byte(APayloadLen shr 56);
    ABuf[3] := Byte(APayloadLen shr 48);
    ABuf[4] := Byte(APayloadLen shr 40);
    ABuf[5] := Byte(APayloadLen shr 32);
    ABuf[6] := Byte(APayloadLen shr 24);
    ABuf[7] := Byte(APayloadLen shr 16);
    ABuf[8] := Byte(APayloadLen shr 8);
    ABuf[9] := Byte(APayloadLen);
    N := 10;
  end;

  if AMasked then
  begin
    ABuf[1] := ABuf[1] or $80;
    ABuf[N]     := Byte(AMaskKey);
    ABuf[N + 1] := Byte(AMaskKey shr 8);
    ABuf[N + 2] := Byte(AMaskKey shr 16);
    ABuf[N + 3] := Byte(AMaskKey shr 24);
    Inc(N, 4);
  end;

  Result := N;
end;

procedure UnmaskNaive(P: PByte; ALen: PtrUInt; ARotKey: UInt32);
var
  I: PtrUInt;
begin
  if ALen = 0 then Exit; // PtrUInt: Len-1 would wrap
  for I := 0 to ALen - 1 do
  begin
    P^ := P^ xor Byte(ARotKey);
    ARotKey := (ARotKey shr 8) or (ARotKey shl 24);
    Inc(P);
  end;
end;

procedure UnmaskU64(P: PByte; ALen: PtrUInt; ARotKey: UInt32);
var
  K64: UInt64;
  P64: PUInt64;
begin
  K64 := UInt64(ARotKey) or (UInt64(ARotKey) shl 32);
  P64 := PUInt64(P);
  // 32 bytes per iteration: four independent XORs keep the single port busy.
  while ALen >= 32 do
  begin
    P64[0] := P64[0] xor K64;
    P64[1] := P64[1] xor K64;
    P64[2] := P64[2] xor K64;
    P64[3] := P64[3] xor K64;
    Inc(P64, 4);
    Dec(ALen, 32);
  end;
  while ALen >= 8 do
  begin
    P64^ := P64^ xor K64;
    Inc(P64);
    Dec(ALen, 8);
  end;
  if ALen > 0 then
    UnmaskNaive(PByte(P64), ALen, ARotKey);
end;

{$if defined(CPUX86_64) and defined(LINUX)}
// SysV AMD64: P=RDI, Len=RSI, RotKey=EDX. 64 bytes per main iteration.
procedure UnmaskSSE2(P: PByte; ALen: PtrUInt; ARotKey: UInt32); assembler; nostackframe;
asm
  movd    xmm0, edx
  pshufd  xmm0, xmm0, 0
@Loop64:
  cmp     rsi, 64
  jb      @Loop16
  movdqu  xmm1, [rdi]
  movdqu  xmm2, [rdi + 16]
  movdqu  xmm3, [rdi + 32]
  movdqu  xmm4, [rdi + 48]
  pxor    xmm1, xmm0
  pxor    xmm2, xmm0
  pxor    xmm3, xmm0
  pxor    xmm4, xmm0
  movdqu  [rdi], xmm1
  movdqu  [rdi + 16], xmm2
  movdqu  [rdi + 32], xmm3
  movdqu  [rdi + 48], xmm4
  add     rdi, 64
  sub     rsi, 64
  jmp     @Loop64
@Loop16:
  cmp     rsi, 16
  jb      @Tail
  movdqu  xmm1, [rdi]
  pxor    xmm1, xmm0
  movdqu  [rdi], xmm1
  add     rdi, 16
  sub     rsi, 16
  jmp     @Loop16
@Tail:
  test    rsi, rsi
  jz      @Done
  movd    eax, xmm0
@TailLoop:
  xor     byte ptr [rdi], al
  ror     eax, 8
  inc     rdi
  dec     rsi
  jnz     @TailLoop
@Done:
end;
{$endif}

procedure ApplyMask(P: PByte; ALen: PtrUInt; AKey: UInt32; AKeyOffset: PtrUInt);
var
  RotKey: UInt32;
  Shift: Integer;
begin
  if ALen = 0 then Exit;
  // Rotate so byte 0 of RotKey is key byte (AKeyOffset mod 4).
  Shift := Integer(AKeyOffset and 3) * 8;
  if Shift = 0 then
    RotKey := AKey
  else
    RotKey := (AKey shr Shift) or (AKey shl (32 - Shift));
{$if defined(CPUX86_64) and defined(LINUX)}
  if ALen >= 16 then
    UnmaskSSE2(P, ALen, RotKey)
  else
{$endif}
    UnmaskU64(P, ALen, RotKey);
end;

end.
