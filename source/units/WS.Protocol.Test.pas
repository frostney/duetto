{ WS.Protocol.Test — the state machine under fire. Two protocols piped
  in-process for echo/close/deflate round trips (the sans-I/O design is
  what makes this possible without a socket); hand-crafted frames for the
  hostile cases: fragmentation rule violations, RSV abuse, masking
  direction, fail-fast UTF-8 (a bad byte in fragment one must kill the
  connection before FIN arrives), close-code policing on the wire, the
  message-size guillotine, and byte-by-byte ingest to exercise every
  carry-buffer path. Wire close codes are asserted by parsing the actual
  queued close frame, not by trusting the property. }

program WS.Protocol.Test;

{$I Shared.inc}

uses
  SysUtils,

  TestingPascalLibrary,
  WS.Frame,
  WS.Handshake,
  WS.Protocol;

type
  TSink = class
  public
    MsgCount: Integer;
    LastText: Boolean;
    LastMsg: TBytes;
    Pings, Pongs: Integer;
    LastPing: TBytes;
    CloseFired: Boolean;
    CloseCode: Word;
    CloseReason: string;
    procedure OnMsg(AText: Boolean; P: PByte; ALen: NativeInt);
    procedure OnPing(P: PByte; ALen: NativeInt);
    procedure OnPong(P: PByte; ALen: NativeInt);
    procedure OnClose(ACode: Word; const AReason: string);
  end;

  TProtoEcho = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestTextRoundTrip;
    procedure TestBinaryRoundTrip;
    procedure TestEmptyText;
    procedure TestPingPong;
    procedure TestByteByByte;
  end;

  TProtoFraming = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestFragmentedAssembly;
    procedure TestControlInterleave;
    procedure TestContWithoutStart;
    procedure TestNewOpcodeMidMessage;
    procedure TestRsv2Fatal;
    procedure TestRsv1WithoutDeflate;
    procedure TestUnmaskedToServer;
    procedure TestMaskedToClient;
  end;

  TProtoUtf8 = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestFailFastMidMessage;
    procedure TestTruncatedAtFin;
    procedure TestSplitCodePointAcrossFragments;
  end;

  TProtoClose = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestCleanClose;
    procedure TestCloseCodeMatrix;
    procedure TestOneByteClosePayload;
    procedure TestBadUtf8CloseReason;
    procedure TestDataAfterCloseIgnored;
    procedure TestOversizeMessage;
  end;

  TProtoDeflate = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestNegotiatedRoundTrip;
    procedure TestCompressedBitOnWire;
    procedure TestLargeCompressible;
    procedure TestByteByByteCompressed;
  end;

const
  CRLF = #13#10;

var
  NoDeflate: TWSDeflateParams;

{ ───────── sink ───────── }

procedure TSink.OnMsg(AText: Boolean; P: PByte; ALen: NativeInt);
begin
  Inc(MsgCount);
  LastText := AText;
  SetLength(LastMsg, ALen);
  if ALen > 0 then Move(P^, LastMsg[0], ALen);
end;

procedure TSink.OnPing(P: PByte; ALen: NativeInt);
begin
  Inc(Pings);
  SetLength(LastPing, ALen);
  if ALen > 0 then Move(P^, LastPing[0], ALen);
end;

procedure TSink.OnPong(P: PByte; ALen: NativeInt);
begin
  Inc(Pongs);
end;

procedure TSink.OnClose(ACode: Word; const AReason: string);
begin
  CloseFired := True;
  CloseCode := ACode;
  CloseReason := AReason;
end;

{ ───────── helpers ───────── }

procedure Wire(ASrc, ADst: TWSProtocol);
var
  Buf: TBytes;
  N: NativeInt;
begin
  N := ASrc.OutPending;
  if N = 0 then Exit;
  SetLength(Buf, N);
  Move(ASrc.OutPtr^, Buf[0], N);
  ASrc.OutConsume(N);
  ADst.Ingest(@Buf[0], N);
end;

procedure Pump(A, B: TWSProtocol);
begin
  while (A.OutPending > 0) or (B.OutPending > 0) do
  begin
    Wire(A, B);
    Wire(B, A);
  end;
end;

function Hook(P: TWSProtocol; S: TSink): TWSProtocol;
begin
  P.OnMessage := S.OnMsg;
  P.OnPing := S.OnPing;
  P.OnPong := S.OnPong;
  P.OnClose := S.OnClose;
  Result := P;
end;

// Craft one frame as a peer would put it on the wire.
function BuildFrame(AOpcode: Byte; AFin, ARsv1, ARsv2, AMasked: Boolean;
  const APayload: TBytes; AKey: UInt32): TBytes;
var
  HLen: Integer;
  N: NativeInt;
begin
  SetLength(Result, WS_MAX_HEADER + Length(APayload));
  HLen := WriteFrameHeader(@Result[0], AFin, ARsv1, AOpcode, AMasked, AKey,
    Length(APayload));
  if ARsv2 then Result[0] := Result[0] or $20;
  N := Length(APayload);
  if N > 0 then
  begin
    Move(APayload[0], Result[HLen], N);
    if AMasked then ApplyMask(@Result[HLen], N, AKey, 0);
  end;
  SetLength(Result, HLen + N);
end;

function Bytes(const S: RawByteString): TBytes;
begin
  SetLength(Result, Length(S));
  if S <> '' then Move(S[1], Result[0], Length(S));
end;

function SameBytes(const A, B: TBytes): Boolean;
begin
  Result := (Length(A) = Length(B)) and
    ((Length(A) = 0) or CompareMem(@A[0], @B[0], Length(A)));
end;

// Parse the close frame a protocol queued and return its wire status code.
// 0 = no close frame found / malformed.
function WireCloseCode(P: TWSProtocol): Word;
var
  Buf: TBytes;
  N, Off: NativeInt;
  H: TWSFrameHeader;
begin
  Result := 0;
  N := P.OutPending;
  if N = 0 then Exit;
  SetLength(Buf, N);
  Move(P.OutPtr^, Buf[0], N);
  Off := 0;
  while Off < N do
  begin
    if ParseFrameHeader(@Buf[Off], N - Off, H) <> wprOK then Exit;
    if Off + H.HeaderLen + NativeInt(H.PayloadLen) > N then Exit;
    if H.Opcode = WS_OP_CLOSE then
    begin
      if H.PayloadLen < 2 then Exit(1005);
      if H.Masked then
        ApplyMask(@Buf[Off + H.HeaderLen], H.PayloadLen, H.MaskKey, 0);
      Result := (UInt32(Buf[Off + H.HeaderLen]) shl 8) or
                Buf[Off + H.HeaderLen + 1];
      Exit;
    end;
    Inc(Off, H.HeaderLen + NativeInt(H.PayloadLen));
  end;
end;

// Fresh server-role protocol with a sink, no deflate.
function NewServer(S: TSink; AMax: NativeInt = 16 * 1024 * 1024): TWSProtocol;
begin
  Result := Hook(TWSProtocol.Create(wsrServer, NoDeflate, AMax), S);
end;

function IngestAll(P: TWSProtocol; const AFrames: array of TBytes): Boolean;
var
  I: Integer;
  Copy_: TBytes;
begin
  Result := True;
  for I := 0 to High(AFrames) do
  begin
    Copy_ := System.Copy(AFrames[I], 0, Length(AFrames[I]));
    if Length(Copy_) > 0 then
      Result := P.Ingest(@Copy_[0], Length(Copy_));
    if not Result then Exit;
  end;
end;

{ ───────── echo ───────── }

procedure TProtoEcho.TestTextRoundTrip;
var
  C, S: TWSProtocol;
  CS, SS: TSink;
begin
  CS := TSink.Create; SS := TSink.Create;
  C := Hook(TWSProtocol.Create(wsrClient, NoDeflate), CS);
  S := Hook(TWSProtocol.Create(wsrServer, NoDeflate), SS);
  try
    C.SendText('grüße aus Bromley');
    Pump(C, S);
    Expect<Integer>(SS.MsgCount).ToBe(1);
    Expect<Boolean>(SS.LastText).ToBe(True);
    Expect<Boolean>(SameBytes(SS.LastMsg, Bytes('grüße aus Bromley'))).ToBe(True);
    // and echo it back the other way
    S.SendText(PByte(@SS.LastMsg[0]), Length(SS.LastMsg));
    Pump(S, C);
    Expect<Integer>(CS.MsgCount).ToBe(1);
    Expect<Boolean>(SameBytes(CS.LastMsg, SS.LastMsg)).ToBe(True);
  finally
    C.Free; S.Free; CS.Free; SS.Free;
  end;
end;

procedure TProtoEcho.TestBinaryRoundTrip;
var
  C, S: TWSProtocol;
  SS: TSink;
  Data: TBytes;
  I: Integer;
begin
  SS := TSink.Create;
  C := TWSProtocol.Create(wsrClient, NoDeflate);
  S := Hook(TWSProtocol.Create(wsrServer, NoDeflate), SS);
  try
    SetLength(Data, 70000); // forces the 64-bit length encoding
    for I := 0 to High(Data) do Data[I] := Byte(I * 31);
    C.SendBinary(@Data[0], Length(Data));
    Pump(C, S);
    Expect<Integer>(SS.MsgCount).ToBe(1);
    Expect<Boolean>(SS.LastText).ToBe(False);
    Expect<Boolean>(SameBytes(SS.LastMsg, Data)).ToBe(True);
  finally
    C.Free; S.Free; SS.Free;
  end;
end;

procedure TProtoEcho.TestEmptyText;
var
  C, S: TWSProtocol;
  SS: TSink;
begin
  SS := TSink.Create;
  C := TWSProtocol.Create(wsrClient, NoDeflate);
  S := Hook(TWSProtocol.Create(wsrServer, NoDeflate), SS);
  try
    C.SendText('');
    Pump(C, S);
    Expect<Integer>(SS.MsgCount).ToBe(1);
    Expect<Integer>(Length(SS.LastMsg)).ToBe(0);
    Expect<Boolean>(SS.LastText).ToBe(True);
  finally
    C.Free; S.Free; SS.Free;
  end;
end;

procedure TProtoEcho.TestPingPong;
var
  C, S: TWSProtocol;
  CS, SS: TSink;
  Payload: TBytes;
begin
  CS := TSink.Create; SS := TSink.Create;
  C := Hook(TWSProtocol.Create(wsrClient, NoDeflate), CS);
  S := Hook(TWSProtocol.Create(wsrServer, NoDeflate), SS);
  try
    Payload := Bytes('marco');
    C.SendPing(@Payload[0], Length(Payload));
    Pump(C, S);
    // server saw the ping and auto-ponged; client saw the pong
    Expect<Integer>(SS.Pings).ToBe(1);
    Expect<Boolean>(SameBytes(SS.LastPing, Payload)).ToBe(True);
    Expect<Integer>(CS.Pongs).ToBe(1);
  finally
    C.Free; S.Free; CS.Free; SS.Free;
  end;
end;

procedure TProtoEcho.TestByteByByte;
var
  C, S: TWSProtocol;
  SS: TSink;
  Buf: TBytes;
  N, I: NativeInt;
begin
  SS := TSink.Create;
  C := TWSProtocol.Create(wsrClient, NoDeflate);
  S := Hook(TWSProtocol.Create(wsrServer, NoDeflate), SS);
  try
    C.SendText('drip-fed över the wire');
    C.SendBinary(nil, 0);
    N := C.OutPending;
    SetLength(Buf, N);
    Move(C.OutPtr^, Buf[0], N);
    C.OutConsume(N);
    for I := 0 to N - 1 do
      Expect<Boolean>(S.Ingest(@Buf[I], 1)).ToBe(True);
    Expect<Integer>(SS.MsgCount).ToBe(2);
    Expect<Boolean>(SameBytes(SS.LastMsg, nil)).ToBe(True);
  finally
    C.Free; S.Free; SS.Free;
  end;
end;

{ ───────── framing rules ───────── }

procedure TProtoFraming.TestFragmentedAssembly;
var
  S: TWSProtocol;
  SS: TSink;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_TEXT, False, False, False, True, Bytes('Hel'), $11223344),
      BuildFrame(WS_OP_CONT, False, False, False, True, Bytes('l'),   $55667788),
      BuildFrame(WS_OP_CONT, True,  False, False, True, Bytes('o'),   $99AABBCC)
    ])).ToBe(True);
    Expect<Integer>(SS.MsgCount).ToBe(1);
    Expect<Boolean>(SameBytes(SS.LastMsg, Bytes('Hello'))).ToBe(True);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoFraming.TestControlInterleave;
var
  S: TWSProtocol;
  SS: TSink;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    // §5.4: control frames MAY be injected mid-fragmented-message.
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_TEXT, False, False, False, True, Bytes('Hel'), $01020304),
      BuildFrame(WS_OP_PING, True,  False, False, True, Bytes('yo'),  $05060708),
      BuildFrame(WS_OP_CONT, True,  False, False, True, Bytes('lo'),  $090A0B0C)
    ])).ToBe(True);
    Expect<Integer>(SS.Pings).ToBe(1);
    Expect<Integer>(SS.MsgCount).ToBe(1);
    Expect<Boolean>(SameBytes(SS.LastMsg, Bytes('Hello'))).ToBe(True);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(0); // no close queued
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoFraming.TestContWithoutStart;
var
  S: TWSProtocol;
  SS: TSink;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_CONT, True, False, False, True, Bytes('x'), $01020304)
    ])).ToBe(False);
    Expect<Boolean>(S.Failed).ToBe(True);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1002);
    Expect<Integer>(Integer(SS.CloseCode)).ToBe(1002);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoFraming.TestNewOpcodeMidMessage;
var
  S: TWSProtocol;
  SS: TSink;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_TEXT, False, False, False, True, Bytes('a'), $01020304),
      BuildFrame(WS_OP_TEXT, True,  False, False, True, Bytes('b'), $05060708)
    ])).ToBe(False);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1002);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoFraming.TestRsv2Fatal;
var
  S: TWSProtocol;
  SS: TSink;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_TEXT, True, False, True, True, Bytes('x'), $01020304)
    ])).ToBe(False);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1002);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoFraming.TestRsv1WithoutDeflate;
var
  S: TWSProtocol;
  SS: TSink;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_TEXT, True, True, False, True, Bytes('x'), $01020304)
    ])).ToBe(False);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1002);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoFraming.TestUnmaskedToServer;
var
  S: TWSProtocol;
  SS: TSink;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_TEXT, True, False, False, False, Bytes('x'), 0)
    ])).ToBe(False);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1002);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoFraming.TestMaskedToClient;
var
  C: TWSProtocol;
  CS: TSink;
begin
  CS := TSink.Create;
  C := Hook(TWSProtocol.Create(wsrClient, NoDeflate), CS);
  try
    Expect<Boolean>(IngestAll(C, [
      BuildFrame(WS_OP_TEXT, True, False, False, True, Bytes('x'), $01020304)
    ])).ToBe(False);
    Expect<Boolean>(C.Failed).ToBe(True);
  finally
    C.Free; CS.Free;
  end;
end;

{ ───────── utf-8 policing ───────── }

procedure TProtoUtf8.TestFailFastMidMessage;
var
  S: TWSProtocol;
  SS: TSink;
  Bad: TBytes;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    // Invalid byte inside a NON-final fragment: a lazy implementation
    // that validates only at FIN would sit on this. We must fail now.
    SetLength(Bad, 2);
    Bad[0] := $C3; Bad[1] := $28; // bad continuation
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_TEXT, False, False, False, True, Bad, $01020304)
    ])).ToBe(False);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1007);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoUtf8.TestTruncatedAtFin;
var
  S: TWSProtocol;
  SS: TSink;
  Trunc_: TBytes;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    SetLength(Trunc_, 1);
    Trunc_[0] := $C3; // lead byte, missing continuation, FIN set
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_TEXT, True, False, False, True, Trunc_, $01020304)
    ])).ToBe(False);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1007);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoUtf8.TestSplitCodePointAcrossFragments;
var
  S: TWSProtocol;
  SS: TSink;
  A, B: TBytes;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    // 'é' = C3 A9 split across the fragment boundary: legal.
    SetLength(A, 2); A[0] := Ord('x'); A[1] := $C3;
    SetLength(B, 1); B[0] := $A9;
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_TEXT, False, False, False, True, A, $01020304),
      BuildFrame(WS_OP_CONT, True,  False, False, True, B, $05060708)
    ])).ToBe(True);
    Expect<Integer>(SS.MsgCount).ToBe(1);
    Expect<Integer>(Length(SS.LastMsg)).ToBe(3);
  finally
    S.Free; SS.Free;
  end;
end;

{ ───────── close handshake ───────── }

procedure TProtoClose.TestCleanClose;
var
  C, S: TWSProtocol;
  CS, SS: TSink;
begin
  CS := TSink.Create; SS := TSink.Create;
  C := Hook(TWSProtocol.Create(wsrClient, NoDeflate), CS);
  S := Hook(TWSProtocol.Create(wsrServer, NoDeflate), SS);
  try
    C.SendClose(1000, 'bye');
    Pump(C, S);
    Expect<Boolean>(SS.CloseFired).ToBe(True);
    Expect<Integer>(Integer(SS.CloseCode)).ToBe(1000);
    Expect<string>(SS.CloseReason).ToBe('bye');
    Expect<Boolean>(S.CloseDone).ToBe(True);
    Expect<Boolean>(C.CloseDone).ToBe(True);
    Expect<Boolean>(C.Failed or S.Failed).ToBe(False);
  finally
    C.Free; S.Free; CS.Free; SS.Free;
  end;
end;

procedure TProtoClose.TestCloseCodeMatrix;
const
  // code, expected-ok
  Cases: array[0..8] of record Code: Word; Ok: Boolean end = (
    (Code: 1000; Ok: True),  (Code: 1003; Ok: True),
    (Code: 1007; Ok: True),  (Code: 1012; Ok: True),
    (Code: 3000; Ok: True),  (Code: 4999; Ok: True),
    (Code: 999;  Ok: False), (Code: 1006; Ok: False),
    (Code: 1015; Ok: False)
  );
var
  S: TWSProtocol;
  SS: TSink;
  I: Integer;
  P: TBytes;
  R: Boolean;
begin
  for I := 0 to High(Cases) do
  begin
    SS := TSink.Create;
    S := NewServer(SS);
    try
      SetLength(P, 2);
      P[0] := Cases[I].Code shr 8;
      P[1] := Cases[I].Code and $FF;
      R := IngestAll(S, [
        BuildFrame(WS_OP_CLOSE, True, False, False, True, P, $01020304)]);
      Expect<Boolean>(R).ToBe(Cases[I].Ok);
      if Cases[I].Ok then
      begin
        Expect<Integer>(Integer(SS.CloseCode)).ToBe(Integer(Cases[I].Code));
        Expect<Integer>(Integer(WireCloseCode(S))).ToBe(Integer(Cases[I].Code));
      end
      else
        Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1002);
    finally
      S.Free; SS.Free;
    end;
  end;
end;

procedure TProtoClose.TestOneByteClosePayload;
var
  S: TWSProtocol;
  SS: TSink;
  P: TBytes;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    SetLength(P, 1); P[0] := $03;
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_CLOSE, True, False, False, True, P, $01020304)
    ])).ToBe(False);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1002);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoClose.TestBadUtf8CloseReason;
var
  S: TWSProtocol;
  SS: TSink;
  P: TBytes;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    SetLength(P, 4);
    P[0] := $03; P[1] := $E8;        // 1000
    P[2] := $C3; P[3] := $28;        // invalid UTF-8 reason
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_CLOSE, True, False, False, True, P, $01020304)
    ])).ToBe(False);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1007);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoClose.TestDataAfterCloseIgnored;
var
  S: TWSProtocol;
  SS: TSink;
  P: TBytes;
begin
  SS := TSink.Create;
  S := NewServer(SS);
  try
    SetLength(P, 2); P[0] := $03; P[1] := $E8; // 1000
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_CLOSE, True, False, False, True, P, $01020304),
      BuildFrame(WS_OP_TEXT,  True, False, False, True, Bytes('late'), $05060708)
    ])).ToBe(True);
    Expect<Integer>(SS.MsgCount).ToBe(0); // the late frame evaporated
    Expect<Boolean>(S.CloseDone).ToBe(True);
  finally
    S.Free; SS.Free;
  end;
end;

procedure TProtoClose.TestOversizeMessage;
var
  S: TWSProtocol;
  SS: TSink;
  Big: TBytes;
begin
  SS := TSink.Create;
  S := NewServer(SS, 64); // 64-byte message cap
  try
    SetLength(Big, 65);
    FillChar(Big[0], 65, Ord('a'));
    Expect<Boolean>(IngestAll(S, [
      BuildFrame(WS_OP_BINARY, True, False, False, True, Big, $01020304)
    ])).ToBe(False);
    Expect<Integer>(Integer(WireCloseCode(S))).ToBe(1009);
  finally
    S.Free; SS.Free;
  end;
end;

{ ───────── permessage-deflate end to end ───────── }

// Run the REAL handshake to get both sides' negotiated params, then build
// the two protocols from them — no hand-assembled TWSDeflateParams.
procedure NegotiatedPair(out C, S: TWSProtocol);
var
  Key, Req, Resp, Err: string;
  HS: TWSServerHandshake;
  CD: TWSDeflateParams;
begin
  Key := ClientGenerateKey;
  Req := ClientBuildRequest('localhost', '/', Key, True);
  if not ServerParseRequest(Req, True, HS) then
    raise Exception.Create('handshake parse failed');
  Resp := ServerBuildResponse(HS);
  if not ClientParseResponse(Resp, Key, True, CD, Err) then
    raise Exception.Create('client parse failed: ' + Err);
  C := TWSProtocol.Create(wsrClient, CD);
  S := TWSProtocol.Create(wsrServer, HS.Deflate);
end;

procedure TProtoDeflate.TestNegotiatedRoundTrip;
var
  C, S: TWSProtocol;
  CS, SS: TSink;
begin
  NegotiatedPair(C, S);
  CS := TSink.Create; SS := TSink.Create;
  Hook(C, CS); Hook(S, SS);
  try
    C.SendText('Komprimierte Grüße — compressed greetings — 圧縮された挨拶');
    Pump(C, S);
    Expect<Integer>(SS.MsgCount).ToBe(1);
    Expect<Boolean>(SS.LastText).ToBe(True);
    S.SendText(PByte(@SS.LastMsg[0]), Length(SS.LastMsg));
    Pump(S, C);
    Expect<Integer>(CS.MsgCount).ToBe(1);
    Expect<Boolean>(SameBytes(CS.LastMsg, SS.LastMsg)).ToBe(True);
  finally
    C.Free; S.Free; CS.Free; SS.Free;
  end;
end;

procedure TProtoDeflate.TestCompressedBitOnWire;
var
  C, S: TWSProtocol;
  H: TWSFrameHeader;
begin
  NegotiatedPair(C, S);
  try
    C.SendText('whatever');
    Expect<Boolean>(ParseFrameHeader(C.OutPtr, C.OutPending, H) = wprOK).ToBe(True);
    Expect<Boolean>(H.Rsv1).ToBe(True);   // RSV1 actually set on the wire
    Expect<Boolean>(H.Masked).ToBe(True); // and the client masked it
  finally
    C.Free; S.Free;
  end;
end;

procedure TProtoDeflate.TestLargeCompressible;
var
  C, S: TWSProtocol;
  SS: TSink;
  Big: TBytes;
  I: Integer;
  CompressedSize: NativeInt;
begin
  NegotiatedPair(C, S);
  SS := TSink.Create;
  Hook(S, SS);
  try
    SetLength(Big, 512 * 1024);
    for I := 0 to High(Big) do Big[I] := Byte(Ord('A') + (I mod 7));
    C.SendBinary(@Big[0], Length(Big));
    CompressedSize := C.OutPending;
    Expect<Boolean>(CompressedSize < Length(Big) div 10).ToBe(True);
    Pump(C, S);
    Expect<Integer>(SS.MsgCount).ToBe(1);
    Expect<Boolean>(SameBytes(SS.LastMsg, Big)).ToBe(True);
  finally
    C.Free; S.Free; SS.Free;
  end;
end;

procedure TProtoDeflate.TestByteByByteCompressed;
var
  C, S: TWSProtocol;
  SS: TSink;
  Buf: TBytes;
  N, I: NativeInt;
begin
  NegotiatedPair(C, S);
  SS := TSink.Create;
  Hook(S, SS);
  try
    C.SendText('drip the deflate stream one byte at a time');
    N := C.OutPending;
    SetLength(Buf, N);
    Move(C.OutPtr^, Buf[0], N);
    C.OutConsume(N);
    for I := 0 to N - 1 do
      Expect<Boolean>(S.Ingest(@Buf[I], 1)).ToBe(True);
    Expect<Integer>(SS.MsgCount).ToBe(1);
    Expect<Boolean>(SameBytes(SS.LastMsg,
      Bytes('drip the deflate stream one byte at a time'))).ToBe(True);
  finally
    C.Free; S.Free; SS.Free;
  end;
end;

{ ───────── registration ───────── }

procedure TProtoEcho.SetupTests;
begin
  Test('text round trips both directions',     TestTextRoundTrip);
  Test('binary 70 KB (64-bit length) echoes',  TestBinaryRoundTrip);
  Test('empty text message',                   TestEmptyText);
  Test('ping is auto-ponged with payload',     TestPingPong);
  Test('byte-by-byte ingest still assembles',  TestByteByByte);
end;

procedure TProtoFraming.SetupTests;
begin
  Test('three-fragment message assembles',     TestFragmentedAssembly);
  Test('ping interleaved mid-message is fine', TestControlInterleave);
  Test('CONT without a message -> 1002',       TestContWithoutStart);
  Test('new opcode mid-message -> 1002',       TestNewOpcodeMidMessage);
  Test('RSV2 -> 1002',                         TestRsv2Fatal);
  Test('RSV1 without deflate -> 1002',         TestRsv1WithoutDeflate);
  Test('unmasked client frame -> 1002',        TestUnmaskedToServer);
  Test('masked server frame fails the client', TestMaskedToClient);
end;

procedure TProtoUtf8.SetupTests;
begin
  Test('bad byte in non-final fragment fails NOW -> 1007',
                                               TestFailFastMidMessage);
  Test('truncated code point at FIN -> 1007',  TestTruncatedAtFin);
  Test('code point split across fragments ok', TestSplitCodePointAcrossFragments);
end;

procedure TProtoClose.SetupTests;
begin
  Test('clean close handshake completes',      TestCleanClose);
  Test('close-code wire matrix',               TestCloseCodeMatrix);
  Test('one-byte close payload -> 1002',       TestOneByteClosePayload);
  Test('bad UTF-8 close reason -> 1007',       TestBadUtf8CloseReason);
  Test('data after close is discarded',        TestDataAfterCloseIgnored);
  Test('message over cap -> 1009',             TestOversizeMessage);
end;

procedure TProtoDeflate.SetupTests;
begin
  Test('negotiated round trip both ways',      TestNegotiatedRoundTrip);
  Test('RSV1 + mask verified on the wire',     TestCompressedBitOnWire);
  Test('512 KB compressible shrinks and echoes', TestLargeCompressible);
  Test('byte-by-byte compressed ingest',       TestByteByByteCompressed);
end;

begin
  NoDeflate.Reset;
  TestRunnerProgram.AddSuite(TProtoEcho.Create('Protocol: echo'));
  TestRunnerProgram.AddSuite(TProtoFraming.Create('Protocol: framing rules'));
  TestRunnerProgram.AddSuite(TProtoUtf8.Create('Protocol: UTF-8 policing'));
  TestRunnerProgram.AddSuite(TProtoClose.Create('Protocol: close handshake'));
  TestRunnerProgram.AddSuite(TProtoDeflate.Create('Protocol: permessage-deflate'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
