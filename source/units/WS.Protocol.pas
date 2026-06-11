unit WS.Protocol;

// Sans-I/O RFC 6455 connection state machine — the heart of lwws.
//
// One TWSProtocol per connection, either role. The owner feeds raw socket
// bytes into Ingest and writes whatever OutPtr/OutPending holds back to the
// socket; the protocol never touches a file descriptor. That makes the
// whole RFC 6455 surface — fragmentation, masking, control interleave,
// fail-fast UTF-8, close-code policing, permessage-deflate — testable
// in-process with no network, and lets the same machine sit behind a
// blocking client, an epoll server, or a bench harness unchanged.
//
// Failure model: Ingest returns False exactly once, after queueing a close
// frame with the appropriate status code (1002 protocol error, 1007 bad
// payload, 1009 too big). The owner flushes the out buffer, then drops TCP.
//
// Ingest MUTATES the buffer it is given (in-place unmask). Socket recv
// buffers are private to their connection, so this costs nothing and
// avoids a copy per frame.

{$I Shared.inc}

interface

uses
  SysUtils,

  WS.Deflate,
  WS.Frame,
  WS.Handshake,
  WS.Utf8;

type
  TWSRole = (wsrServer, wsrClient);

  // P/Len point into protocol-owned buffers, valid only for the duration
  // of the callback. Copy if you need to keep the bytes.
  TWSMessageEvent = procedure(AText: Boolean; P: PByte; Len: NativeInt) of object;
  TWSControlEvent = procedure(P: PByte; Len: NativeInt) of object;
  TWSCloseEvent   = procedure(ACode: Word; const AReason: string) of object;

  TWSProtocol = class
  private
    FRole: TWSRole;
    FMaxMessage: NativeInt;

    // inbound reassembly
    FCarry: TBytes;            // partial header / control frame from prior Ingest
    FCarryLen: NativeInt;
    FMsg: TBytes;              // assembled uncompressed message
    FMsgLen: NativeInt;
    FInMessage: Boolean;
    FMsgText: Boolean;
    FMsgCompressed: Boolean;
    FUtf8: UInt32;

    // data-frame payload being streamed (header already consumed). Data
    // payloads never enter the carry buffer: each chunk is unmasked in
    // the caller's buffer and routed straight to assembly/inflater.
    FStreamRemaining: UInt64;
    FStreamFin: Boolean;
    FStreamMasked: Boolean;
    FStreamKey: UInt32;
    FStreamOff: PtrUInt;       // mask phase within the frame payload

    // outbound queue
    FOut: TBytes;
    FOutOff, FOutLen: NativeInt;

    // close / failure state
    FCloseSent, FCloseReceived, FFailed, FDrain: Boolean;
    FCloseCode: Word;
    FCloseReason: string;

    // permessage-deflate (nil when not negotiated)
    FDeflater: TWSDeflater;
    FInflater: TWSInflater;

    // client mask-key PRNG (xorshift128, urandom-seeded)
    FRng: array[0..3] of UInt32;

    FOnMessage: TWSMessageEvent;
    FOnPing, FOnPong: TWSControlEvent;
    FOnClose: TWSCloseEvent;

    function NextMaskKey: UInt32;
    procedure OutAppend(P: PByte; ALen: NativeInt);
    procedure SendFrame(AOpcode: Byte; ARsv1: Boolean; P: PByte; ALen: NativeInt);
    procedure SendDataMessage(AOpcode: Byte; P: PByte; ALen: NativeInt);
    function Fail(ACode: Word; const AReason: string): Boolean;
    procedure QueueClose(ACode: Word; const AReason: string);
    function HandleControl(const H: TWSFrameHeader; P: PByte): Boolean;
    function BeginDataFrame(const H: TWSFrameHeader): Boolean;
    function DataChunk(P: PByte; ALen: NativeInt): Boolean;
    function FinishMessage: Boolean;
  public
    constructor Create(ARole: TWSRole; const ADeflate: TWSDeflateParams;
      AMaxMessage: NativeInt = 16 * 1024 * 1024);
    destructor Destroy; override;

    // Feed bytes read from the socket. Mutates the buffer. False means the
    // connection has failed: flush the out queue, then close TCP.
    function Ingest(P: PByte; ALen: NativeInt): Boolean;

    procedure SendText(const S: RawByteString); overload;
    procedure SendText(P: PByte; ALen: NativeInt); overload;
    procedure SendBinary(P: PByte; ALen: NativeInt);
    procedure SendPing(P: PByte; ALen: NativeInt);
    procedure SendPong(P: PByte; ALen: NativeInt);
    procedure SendClose(ACode: Word = 1000; const AReason: string = '');

    // Enqueue raw pre-framed bytes (e.g. the server's 101 response) so they
    // share the out queue's backpressure path. Bytes go out before any
    // frame queued afterwards.
    procedure QueueRaw(P: PByte; ALen: NativeInt);

    // Outbound bytes awaiting the socket. Write from OutPtr^, then
    // OutConsume(however many the socket took).
    function OutPtr: PByte; inline;
    function OutPending: NativeInt; inline;
    procedure OutConsume(N: NativeInt);

    // Both close frames exchanged (or we failed): time to drop TCP.
    function CloseDone: Boolean; inline;

    property Role: TWSRole read FRole;
    property Failed: Boolean read FFailed;
    property CloseSent: Boolean read FCloseSent;
    property CloseReceived: Boolean read FCloseReceived;
    property CloseCode: Word read FCloseCode;
    property CloseReason: string read FCloseReason;

    property OnMessage: TWSMessageEvent read FOnMessage write FOnMessage;
    property OnPing: TWSControlEvent read FOnPing write FOnPing;
    property OnPong: TWSControlEvent read FOnPong write FOnPong;
    property OnClose: TWSCloseEvent read FOnClose write FOnClose;
  end;

// §7.4: is this status code permitted in a close frame on the wire?
// 1004/1005/1006/1015 are reserved for local reporting only; 1012-1014
// were registered post-RFC (load balancer signals) and are accepted.
function WSValidCloseCode(ACode: Word): Boolean;

implementation

function WSValidCloseCode(ACode: Word): Boolean;
begin
  case ACode of
    1000..1003, 1007..1014: Result := True;
    3000..4999:             Result := True;
  else
    Result := False;
  end;
end;

{ TWSProtocol }

constructor TWSProtocol.Create(ARole: TWSRole;
  const ADeflate: TWSDeflateParams; AMaxMessage: NativeInt);
var
  OwnBits, PeerBits: Integer;
  OwnNoCtx, PeerNoCtx: Boolean;
begin
  inherited Create;
  FRole := ARole;
  FMaxMessage := AMaxMessage;
  FCloseCode := 1005; // "no status received" until told otherwise

  if ADeflate.Enabled then
  begin
    // Each side compresses with its own window/takeover params and
    // inflates with the peer's.
    if ARole = wsrServer then
    begin
      OwnBits := ADeflate.ServerMaxBits;   OwnNoCtx := ADeflate.ServerNoTakeover;
      PeerBits := ADeflate.ClientMaxBits;  PeerNoCtx := ADeflate.ClientNoTakeover;
    end
    else
    begin
      OwnBits := ADeflate.ClientMaxBits;   OwnNoCtx := ADeflate.ClientNoTakeover;
      PeerBits := ADeflate.ServerMaxBits;  PeerNoCtx := ADeflate.ServerNoTakeover;
    end;
    FDeflater := TWSDeflater.Create(OwnBits, OwnNoCtx);
    FInflater := TWSInflater.Create(PeerBits, PeerNoCtx, AMaxMessage);
  end;

  if ARole = wsrClient then
  begin
    repeat
      WSRandomBytes(@FRng[0], SizeOf(FRng));
    until (FRng[0] or FRng[1] or FRng[2] or FRng[3]) <> 0;
  end;
end;

destructor TWSProtocol.Destroy;
begin
  FDeflater.Free;
  FInflater.Free;
  inherited;
end;

function TWSProtocol.NextMaskKey: UInt32;
var
  T: UInt32;
begin
  // xorshift128 (Marsaglia) — mask keys need unpredictability across a
  // connection, not cryptographic strength; the seed is urandom.
  T := FRng[3];
  T := T xor (T shl 11);
  T := T xor (T shr 8);
  FRng[3] := FRng[2]; FRng[2] := FRng[1]; FRng[1] := FRng[0];
  Result := T xor FRng[0] xor (FRng[0] shr 19);
  FRng[0] := Result;
end;

function TWSProtocol.OutPtr: PByte;
begin
  if FOutLen > FOutOff then
    Result := @FOut[FOutOff]
  else
    Result := nil;
end;

function TWSProtocol.OutPending: NativeInt;
begin
  Result := FOutLen - FOutOff;
end;

procedure TWSProtocol.OutConsume(N: NativeInt);
begin
  Inc(FOutOff, N);
  if FOutOff >= FOutLen then
  begin
    FOutOff := 0;
    FOutLen := 0;
  end;
end;

procedure TWSProtocol.QueueRaw(P: PByte; ALen: NativeInt);
begin
  OutAppend(P, ALen);
end;

procedure TWSProtocol.OutAppend(P: PByte; ALen: NativeInt);
var
  Need: NativeInt;
begin
  if ALen <= 0 then Exit;
  // Compact first if the dead prefix dominates the buffer.
  if (FOutOff > 0) and (FOutOff * 2 > FOutLen) then
  begin
    Move(FOut[FOutOff], FOut[0], FOutLen - FOutOff);
    Dec(FOutLen, FOutOff);
    FOutOff := 0;
  end;
  Need := FOutLen + ALen;
  if Need > Length(FOut) then
    SetLength(FOut, Need + Need shr 1 + 256);
  Move(P^, FOut[FOutLen], ALen);
  Inc(FOutLen, ALen);
end;

procedure TWSProtocol.SendFrame(AOpcode: Byte; ARsv1: Boolean;
  P: PByte; ALen: NativeInt);
var
  Hdr: array[0..WS_MAX_HEADER - 1] of Byte;
  HLen: Integer;
  Key: UInt32;
  PayloadAt: NativeInt;
begin
  if FRole = wsrClient then
  begin
    Key := NextMaskKey;
    HLen := WriteFrameHeader(@Hdr[0], True, ARsv1, AOpcode, True, Key, ALen);
    OutAppend(@Hdr[0], HLen);
    PayloadAt := FOutLen;
    OutAppend(P, ALen);
    // Mask the copy that now lives in our out buffer — never the caller's.
    ApplyMask(@FOut[PayloadAt], ALen, Key, 0);
  end
  else
  begin
    HLen := WriteFrameHeader(@Hdr[0], True, ARsv1, AOpcode, False, 0, ALen);
    OutAppend(@Hdr[0], HLen);
    OutAppend(P, ALen);
  end;
end;

procedure TWSProtocol.SendDataMessage(AOpcode: Byte; P: PByte; ALen: NativeInt);
var
  Z: TBytes;
  ZP: PByte;
begin
  if FCloseSent then Exit;
  if FDeflater <> nil then
  begin
    if not FDeflater.CompressMessage(P, ALen, Z) then Exit; // deflater dead
    if Length(Z) > 0 then ZP := @Z[0] else ZP := nil;
    SendFrame(AOpcode, True, ZP, Length(Z));
  end
  else
    SendFrame(AOpcode, False, P, ALen);
end;

procedure TWSProtocol.SendText(const S: RawByteString);
begin
  if S <> '' then
    SendDataMessage(WS_OP_TEXT, PByte(@S[1]), Length(S))
  else
    SendDataMessage(WS_OP_TEXT, nil, 0);
end;

procedure TWSProtocol.SendText(P: PByte; ALen: NativeInt);
begin
  SendDataMessage(WS_OP_TEXT, P, ALen);
end;

procedure TWSProtocol.SendBinary(P: PByte; ALen: NativeInt);
begin
  SendDataMessage(WS_OP_BINARY, P, ALen);
end;

procedure TWSProtocol.SendPing(P: PByte; ALen: NativeInt);
begin
  if (not FCloseSent) and (ALen <= 125) then
    SendFrame(WS_OP_PING, False, P, ALen);
end;

procedure TWSProtocol.SendPong(P: PByte; ALen: NativeInt);
begin
  if (not FCloseSent) and (ALen <= 125) then
    SendFrame(WS_OP_PONG, False, P, ALen);
end;

procedure TWSProtocol.QueueClose(ACode: Word; const AReason: string);
var
  Buf: array[0..124] of Byte;
  N: NativeInt;
begin
  if FCloseSent then Exit;
  FCloseSent := True;
  if ACode = 1005 then
    SendFrame(WS_OP_CLOSE, False, nil, 0)  // echo "no status" as empty
  else
  begin
    Buf[0] := ACode shr 8;
    Buf[1] := ACode and $FF;
    N := Length(AReason);
    if N > 123 then N := 123;
    if N > 0 then Move(AReason[1], Buf[2], N);
    SendFrame(WS_OP_CLOSE, False, @Buf[0], N + 2);
  end;
end;

procedure TWSProtocol.SendClose(ACode: Word; const AReason: string);
begin
  if not FCloseSent then
  begin
    FCloseCode := ACode;
    FCloseReason := AReason;
    QueueClose(ACode, AReason);
  end;
end;

function TWSProtocol.Fail(ACode: Word; const AReason: string): Boolean;
begin
  FFailed := True;
  FDrain := True;
  FCloseCode := ACode;
  FCloseReason := AReason;
  QueueClose(ACode, AReason);
  if Assigned(FOnClose) then FOnClose(ACode, AReason);
  Result := False;
end;

function TWSProtocol.CloseDone: Boolean;
begin
  Result := FFailed or (FCloseSent and FCloseReceived);
end;

function TWSProtocol.HandleControl(const H: TWSFrameHeader; P: PByte): Boolean;
var
  Code: Word;
  Reason: string;
  N: NativeInt;
  U: UInt32;
begin
  Result := True;
  case H.Opcode of
    WS_OP_PING:
      begin
        SendPong(P, H.PayloadLen);
        if Assigned(FOnPing) then FOnPing(P, H.PayloadLen);
      end;
    WS_OP_PONG:
      if Assigned(FOnPong) then FOnPong(P, H.PayloadLen);
    WS_OP_CLOSE:
      begin
        case H.PayloadLen of
          0: begin Code := 1005; Reason := ''; end;
          1: Exit(Fail(1002, 'close payload of one byte'));
        else
          Code := (UInt32(P[0]) shl 8) or P[1];
          if not WSValidCloseCode(Code) then
            Exit(Fail(1002, 'invalid close code'));
          N := H.PayloadLen - 2;
          U := UTF8_ACCEPT;
          if (not Utf8Advance(U, P + 2, N)) or (U <> UTF8_ACCEPT) then
            Exit(Fail(1007, 'close reason is not UTF-8'));
          SetLength(Reason, N);
          if N > 0 then Move(P[2], Reason[1], N);
        end;
        FCloseReceived := True;
        FDrain := True;
        if not FCloseSent then
        begin
          FCloseCode := Code;
          FCloseReason := Reason;
          QueueClose(Code, '');
        end;
        if Assigned(FOnClose) then FOnClose(Code, Reason);
      end;
  end;
end;

function TWSProtocol.FinishMessage: Boolean;
var
  P: PByte;
  N, Prev: NativeInt;
begin
  Result := True;
  if FMsgCompressed then
  begin
    Prev := FInflater.OutSize;
    if not FInflater.Finish then
    begin
      if FInflater.OutSize >= FMaxMessage then
        Exit(Fail(1009, 'message too big'))
      else
        Exit(Fail(1007, 'invalid deflate stream'));
    end;
    N := FInflater.OutSize;
    if N > 0 then P := @FInflater.OutData[0] else P := nil;
    if FMsgText then
    begin
      if (N > Prev) and
         (not Utf8Advance(FUtf8, P + Prev, N - Prev)) then
        Exit(Fail(1007, 'invalid UTF-8'));
      if FUtf8 <> UTF8_ACCEPT then
        Exit(Fail(1007, 'truncated UTF-8 at message end'));
    end;
  end
  else
  begin
    if FMsgText and (FUtf8 <> UTF8_ACCEPT) then
      Exit(Fail(1007, 'truncated UTF-8 at message end'));
    N := FMsgLen;
    if N > 0 then P := @FMsg[0] else P := nil;
  end;
  FInMessage := False;
  FMsgLen := 0;
  if Assigned(FOnMessage) then FOnMessage(FMsgText, P, N);
end;

function TWSProtocol.BeginDataFrame(const H: TWSFrameHeader): Boolean;
begin
  Result := True;

  if H.Opcode = WS_OP_CONT then
  begin
    if not FInMessage then
      Exit(Fail(1002, 'continuation without a message'));
  end
  else
  begin
    if FInMessage then
      Exit(Fail(1002, 'new data opcode inside a fragmented message'));
    FInMessage := True;
    FMsgText := H.Opcode = WS_OP_TEXT;
    FMsgCompressed := H.Rsv1;
    FUtf8 := UTF8_ACCEPT;
    FMsgLen := 0;
    if FMsgCompressed then
      FInflater.BeginMessage;
  end;

  // Cumulative uncompressed cap, checked at header time so an oversize
  // message dies before a payload byte is buffered. Compressed messages
  // are governed by the inflater's output cap instead.
  if not FMsgCompressed then
    if FMsgLen + NativeInt(H.PayloadLen) > FMaxMessage then
      Exit(Fail(1009, 'message too big'));
end;

function TWSProtocol.DataChunk(P: PByte; ALen: NativeInt): Boolean;
var
  Prev, Need: NativeInt;
begin
  Result := True;
  if ALen = 0 then Exit;

  if FMsgCompressed then
  begin
    Prev := FInflater.OutSize;
    if not FInflater.Feed(P, ALen) then
    begin
      if FInflater.OutSize >= FMaxMessage then
        Exit(Fail(1009, 'message too big'))
      else
        Exit(Fail(1007, 'invalid deflate stream'));
    end;
    // Fail-fast UTF-8 over whatever the inflater just produced.
    if FMsgText and (FInflater.OutSize > Prev) then
      if not Utf8Advance(FUtf8, @FInflater.OutData[Prev],
                         FInflater.OutSize - Prev) then
        Exit(Fail(1007, 'invalid UTF-8'));
  end
  else
  begin
    if FMsgText then
      if not Utf8Advance(FUtf8, P, ALen) then
        Exit(Fail(1007, 'invalid UTF-8'));
    Need := FMsgLen + ALen;
    if Need > Length(FMsg) then
      SetLength(FMsg, Need + Need shr 1 + 64);
    Move(P^, FMsg[FMsgLen], ALen);
    FMsgLen := Need;
  end;
end;

function TWSProtocol.Ingest(P: PByte; ALen: NativeInt): Boolean;
var
  Work: PByte;
  WLen, Off, FrameEnd, Take: NativeInt;
  H: TWSFrameHeader;
  R: TWSParseResult;
  FromCarry: Boolean;

  procedure Stash(ASrc: PByte; N: NativeInt);
  begin
    if N > Length(FCarry) then
      SetLength(FCarry, N + N shr 1 + WS_MAX_HEADER);
    if (N > 0) and (ASrc <> @FCarry[0]) then
      Move(ASrc^, FCarry[0], N);
    FCarryLen := N;
  end;

begin
  Result := True;
  if FFailed then Exit(False);
  if ALen <= 0 then Exit;

  if FDrain then Exit; // close already received: peer bytes are noise now

  if FCarryLen > 0 then
  begin
    // Splice: partial header / control frame + new bytes. Data payloads
    // never sit in the carry, so this stays small (header + 125 max).
    if FCarryLen + ALen > Length(FCarry) then
      SetLength(FCarry, FCarryLen + ALen);
    Move(P^, FCarry[FCarryLen], ALen);
    Inc(FCarryLen, ALen);
    Work := @FCarry[0];
    WLen := FCarryLen;
    FromCarry := True;
  end
  else
  begin
    Work := P;
    WLen := ALen;
    FromCarry := False;
  end;

  Off := 0;
  while True do
  begin
    // A data frame mid-payload: stream chunks straight through, unmasking
    // in place with the mask phase carried across Ingest calls. No copy
    // into carry, no header reparse.
    if FStreamRemaining > 0 then
    begin
      Take := WLen - Off;
      if Take <= 0 then Break;
      if UInt64(Take) > FStreamRemaining then
        Take := NativeInt(FStreamRemaining);
      if FStreamMasked then
        ApplyMask(Work + Off, Take, FStreamKey, FStreamOff);
      Inc(FStreamOff, Take);
      Dec(FStreamRemaining, Take);
      if not DataChunk(Work + Off, Take) then Exit(False);
      Inc(Off, Take);
      if (FStreamRemaining = 0) and FStreamFin then
        if not FinishMessage then Exit(False);
      Continue;
    end;

    if Off >= WLen then Break;

    R := ParseFrameHeader(Work + Off, WLen - Off, H);
    case R of
      wprProtocolError:
        Exit(Fail(1002, 'malformed frame header'));
      wprNeedMore:
        Break;
    end;

    // Police RSV before anything else (§5.2).
    if H.Rsv2 or H.Rsv3 then
      Exit(Fail(1002, 'reserved bits set'));
    if H.Rsv1 then
      if (FInflater = nil) or H.IsControl or (H.Opcode = WS_OP_CONT) then
        Exit(Fail(1002, 'unexpected RSV1'));

    // Masking direction (§5.1).
    if FRole = wsrServer then
    begin
      if not H.Masked then
        Exit(Fail(1002, 'client frame not masked'));
    end
    else if H.Masked then
      Exit(Fail(1002, 'server frame masked'));

    // Oversize data frames die before we touch a byte of them.
    if not H.IsControl then
      if NativeInt(H.PayloadLen) > FMaxMessage then
        Exit(Fail(1009, 'frame exceeds message cap'));

    if H.IsControl then
    begin
      // Control frames are tiny (<= 125) and processed whole.
      FrameEnd := Off + H.HeaderLen + NativeInt(H.PayloadLen);
      if FrameEnd > WLen then Break; // wait for the rest
      if H.Masked and (H.PayloadLen > 0) then
        ApplyMask(Work + Off + H.HeaderLen, H.PayloadLen, H.MaskKey, 0);
      if not HandleControl(H, Work + Off + H.HeaderLen) then Exit(False);
      if FDrain then
      begin
        FCarryLen := 0; // close consumed; anything after it is discarded
        Exit(True);
      end;
      Off := FrameEnd;
    end
    else
    begin
      if not BeginDataFrame(H) then Exit(False);
      FStreamRemaining := H.PayloadLen;
      FStreamFin := H.Fin;
      FStreamMasked := H.Masked;
      FStreamKey := H.MaskKey;
      FStreamOff := 0;
      Inc(Off, H.HeaderLen);
      if (FStreamRemaining = 0) and FStreamFin then
        if not FinishMessage then Exit(False);
      // loop re-enters the streaming branch for the payload (if any)
    end;
  end;

  // Keep whatever is left for the next read: at most a partial header or
  // a split control frame.
  if Off < WLen then
  begin
    if FromCarry and (Off > 0) then
      Move(FCarry[Off], FCarry[0], WLen - Off);
    if not FromCarry then
      Stash(Work + Off, WLen - Off)
    else
      FCarryLen := WLen - Off;
  end
  else
    FCarryLen := 0;
end;

end.
