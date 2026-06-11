unit WS.Utf8;

// Streaming UTF-8 validation (Bjoern Hoehrmann's DFA, the same automaton
// tungstenite and websocket.zig use). One table lookup + one transition
// per byte; state survives across fragment and TCP-read boundaries, which
// is what RFC 6455 §8.1 needs — a text message must be validated even when
// a code point is split across frames.
//
// UTF8_ACCEPT (0)  — valid so far, ends on a code point boundary.
// UTF8_REJECT (12) — invalid; unrecoverable.
// Anything else    — valid so far, mid code point (only OK mid-message).

{$I Shared.inc}

interface

const
  UTF8_ACCEPT = 0;
  UTF8_REJECT = 12;

// Feed Len bytes; returns False as soon as the DFA hits REJECT.
// On the ACCEPT state, runs of ASCII are consumed 8 bytes per iteration
// (high-bit word scan — the scalar cousin of what simdutf8 does); the DFA
// only sees bytes >= $80 and their neighbourhood.
function Utf8Advance(var AState: UInt32; P: PByte; ALen: PtrUInt): Boolean;

// The plain one-lookup-per-byte automaton, exported so the tests can assert
// equivalence with the fast-path version and wsbench can race the two.
function Utf8AdvanceDFA(var AState: UInt32; P: PByte; ALen: PtrUInt): Boolean;

// Convenience: whole-buffer check (must end on a boundary).
function Utf8Valid(P: PByte; ALen: PtrUInt): Boolean;

implementation

const
  // Byte -> character class.
  Utf8Class: array[0..255] of Byte = (
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8);

  // (state, class) -> state; states premultiplied by 12. Derived from the
  // class partition above rather than copied: 0=ACCEPT, 12=REJECT,
  // 24/36/48 = N continuations of any kind remaining, 60 = after E0
  // (continuation must be A0-BF, else overlong), 72 = after ED (must be
  // 80-9F, else surrogate), 84 = after F0 (must be 90-BF, else overlong),
  // 96 = after F4 (must be 80-8F, else > U+10FFFF).
  // Class order per row: 0,1,2,3,4,5,6,7,8,9,10,11.
  Utf8Trans: array[0..107] of Byte = (
     0,12,24,36,72,96,48,12,12,12,60,84,   // ACCEPT
    12,12,12,12,12,12,12,12,12,12,12,12,   // REJECT (absorbing)
    12, 0,12,12,12,12,12, 0,12, 0,12,12,   // need 1 continuation
    12,24,12,12,12,12,12,24,12,24,12,12,   // need 2
    12,36,12,12,12,12,12,36,12,36,12,12,   // need 3
    12,12,12,12,12,12,12,24,12,12,12,12,   // after E0: only A0-BF
    12,24,12,12,12,12,12,12,12,24,12,12,   // after ED: only 80-9F
    12,12,12,12,12,12,12,36,12,36,12,12,   // after F0: only 90-BF
    12,36,12,12,12,12,12,12,12,12,12,12);  // after F4: only 80-8F

function Utf8AdvanceDFA(var AState: UInt32; P: PByte; ALen: PtrUInt): Boolean;
var
  S: UInt32;
begin
  S := AState;
  while ALen > 0 do
  begin
    S := Utf8Trans[S + Utf8Class[P^]];
    if S = UTF8_REJECT then
    begin
      AState := S;
      Exit(False);
    end;
    Inc(P);
    Dec(ALen);
  end;
  AState := S;
  Result := True;
end;

function Utf8Advance(var AState: UInt32; P: PByte; ALen: PtrUInt): Boolean;
const
  HighBits = UInt64($8080808080808080);
var
  S: UInt32;
  Chunk: UInt64;
begin
  S := AState;
  while ALen > 0 do
  begin
    if S = UTF8_ACCEPT then
    begin
      // ASCII fast path: 8 bytes at a time while every high bit is clear.
      // Unaligned loads are fine on x86-64/AArch64 (our targets).
      while ALen >= 8 do
      begin
        Move(P^, Chunk, 8);
        if (Chunk and HighBits) <> 0 then Break;
        Inc(P, 8);
        Dec(ALen, 8);
      end;
      if ALen = 0 then Break;
    end;
    S := Utf8Trans[S + Utf8Class[P^]];
    if S = UTF8_REJECT then
    begin
      AState := S;
      Exit(False);
    end;
    Inc(P);
    Dec(ALen);
  end;
  AState := S;
  Result := True;
end;

function Utf8Valid(P: PByte; ALen: PtrUInt): Boolean;
var
  S: UInt32;
begin
  S := UTF8_ACCEPT;
  Result := Utf8Advance(S, P, ALen) and (S = UTF8_ACCEPT);
end;

end.
