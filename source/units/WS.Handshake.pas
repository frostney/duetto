unit WS.Handshake;

// RFC 6455 §4 opening handshake, both roles, plus RFC 7692
// permessage-deflate offer/response negotiation. Pure string work —
// transports feed it raw header blocks.

{$I Shared.inc}

interface

const
  WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
  WS_MAX_HANDSHAKE = 8192; // cap on accumulated request headers

type
  TWSDeflateParams = record
    Enabled: Boolean;
    ServerNoTakeover: Boolean;  // our compressor resets per message (server role)
    ClientNoTakeover: Boolean;  // peer compressor resets per message
    ServerMaxBits: Integer;     // window bits our compressor uses, 9..15
    ClientMaxBits: Integer;     // window bits peer compressor uses, 9..15
    procedure Reset;
  end;

  TWSServerHandshake = record
    Path: string;
    Host: string;
    Key: string;
    Version: Integer;
    Protocols: string;          // raw Sec-WebSocket-Protocol value (app decides)
    Deflate: TWSDeflateParams;  // negotiated result (Enabled=False if none)
    Failure: string;            // set when parse returns False
  end;

// Returns the offset just past the terminating CRLFCRLF, or 0 if not yet
// complete.
function HandshakeFindEnd(ABuf: PByte; ALen: Integer): Integer; overload;
function HandshakeFindEnd(const S: RawByteString): Integer; overload;

function ComputeAccept(const AKey: string): string;

// --- server role ---------------------------------------------------------
function ServerParseRequest(const ARaw: RawByteString; AAllowDeflate: Boolean;
  out AHS: TWSServerHandshake): Boolean;
function ServerBuildResponse(const AHS: TWSServerHandshake): RawByteString;
function ServerBuildReject(ACode: Integer; const AReason: string): RawByteString;

// --- client role ---------------------------------------------------------
// Crypto-quality random bytes (/dev/urandom on Unix, Randomize fallback).
// Exported for WS.Protocol's client-side mask-key generation.
procedure WSRandomBytes(P: PByte; N: Integer);
function ClientGenerateKey: string;
function ClientBuildRequest(const AHost, APath, AKey: string;
  AOfferDeflate: Boolean): string;
// AOfferedDeflate must mirror what ClientBuildRequest was called with:
// a server selecting an extension the client never offered is a §4.1
// connection failure.
function ClientParseResponse(const ARaw, AKey: string;
  AOfferedDeflate: Boolean;
  out ADeflate: TWSDeflateParams; out AErr: string): Boolean;

implementation

uses
  SysUtils,

  sha1;

// Plain table base64 — the FCL's EncodeStringBase64 routes through two
// stream objects per call, which is two heap allocations too many for a
// 20-byte digest on the connection-setup path.
const
  B64: array[0..63] of AnsiChar =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function Base64Encode(P: PByte; ALen: Integer): string;
var
  I, O: Integer;
  B: UInt32;
begin
  SetLength(Result, ((ALen + 2) div 3) * 4);
  I := 0;
  O := 1;
  while I + 3 <= ALen do
  begin
    B := (UInt32(P[I]) shl 16) or (UInt32(P[I + 1]) shl 8) or P[I + 2];
    Result[O] := B64[(B shr 18) and 63];
    Result[O + 1] := B64[(B shr 12) and 63];
    Result[O + 2] := B64[(B shr 6) and 63];
    Result[O + 3] := B64[B and 63];
    Inc(I, 3);
    Inc(O, 4);
  end;
  case ALen - I of
    1:
    begin
      B := UInt32(P[I]) shl 16;
      Result[O] := B64[(B shr 18) and 63];
      Result[O + 1] := B64[(B shr 12) and 63];
      Result[O + 2] := '=';
      Result[O + 3] := '=';
    end;
    2:
    begin
      B := (UInt32(P[I]) shl 16) or (UInt32(P[I + 1]) shl 8);
      Result[O] := B64[(B shr 18) and 63];
      Result[O + 1] := B64[(B shr 12) and 63];
      Result[O + 2] := B64[(B shr 6) and 63];
      Result[O + 3] := '=';
    end;
  end;
end;

// Append-into-stack-buffer builder for the request/response constructors.
// FPC routes `LocalStr := Func(...)` through a nil hidden temporary, so a
// function built from repeated `Result := Result + ...` reallocates per
// append AND per call when assigned to a procedure-local — measured at 9x
// the cost of the same call assigned to a global. Building into a fixed
// buffer and materialising the string once makes the cost identical
// regardless of the caller's destination. 2 KiB is ample: our own
// constructors emit < 300 bytes plus caller-supplied host/path, and the
// inbound parser caps whole header blocks at WS_MAX_HANDSHAKE anyway.
type
  TWSStrBuilder = record
    Buf: array[0..2047] of AnsiChar;
    Len: Integer;
    procedure App(const S: string); inline;
    function Done: string;
  end;

procedure TWSStrBuilder.App(const S: string);
var
  N: Integer;
begin
  N := Length(S);
  if Len + N > SizeOf(Buf) then
    N := SizeOf(Buf) - Len; // clamp; cannot occur for protocol-valid input
  if N > 0 then
  begin
    Move(S[1], Buf[Len], N);
    Inc(Len, N);
  end;
end;

function TWSStrBuilder.Done: string;
begin
  SetString(Result, PAnsiChar(@Buf[0]), Len);
end;


procedure TWSDeflateParams.Reset;
begin
  Enabled := False;
  ServerNoTakeover := False;
  ClientNoTakeover := False;
  ServerMaxBits := 15;
  ClientMaxBits := 15;
end;

function HandshakeFindEnd(ABuf: PByte; ALen: Integer): Integer; overload;
var
  I: Integer;
begin
  Result := 0;
  for I := 0 to ALen - 4 do
    if (ABuf[I] = 13) and (ABuf[I + 1] = 10) and
       (ABuf[I + 2] = 13) and (ABuf[I + 3] = 10) then
      Exit(I + 4);
end;

function HandshakeFindEnd(const S: RawByteString): Integer; overload;
begin
  if S = '' then Exit(0);
  Result := HandshakeFindEnd(PByte(@S[1]), Length(S));
end;

function ComputeAccept(const AKey: string): string;
var
  Digest: TSHA1Digest;
begin
  Digest := SHA1String(AKey + WS_GUID);
  Result := Base64Encode(@Digest, 20);
end;

// --- small header helpers -------------------------------------------------

function SameTextTrim(const A, B: string): Boolean;
begin
  Result := SameText(Trim(A), B);
end;

// Comma-separated token list contains AToken (case-insensitive)?
function TokenListHas(const AValue, AToken: string): Boolean;
var
  Rest, Item: string;
  P: Integer;
begin
  Result := False;
  Rest := AValue;
  while Rest <> '' do
  begin
    P := Pos(',', Rest);
    if P = 0 then
    begin
      Item := Rest;
      Rest := '';
    end
    else
    begin
      Item := Copy(Rest, 1, P - 1);
      Rest := Copy(Rest, P + 1, MaxInt);
    end;
    if SameTextTrim(Item, AToken) then Exit(True);
  end;
end;

// Collect every value of header AName (case-insensitive) from a raw header
// block, joined with ', ' — RFC 7230 list semantics, needed because clients
// may split Sec-WebSocket-Extensions across multiple header lines.
function HeaderValue(const ARaw, AName: string): string;
var
  LineStart, I, Colon: Integer;
  Line, N: string;
begin
  Result := '';
  LineStart := 1;
  for I := 1 to Length(ARaw) do
    if ARaw[I] = #10 then
    begin
      Line := Copy(ARaw, LineStart, I - LineStart);
      if (Line <> '') and (Line[Length(Line)] = #13) then
        SetLength(Line, Length(Line) - 1);
      LineStart := I + 1;
      Colon := Pos(':', Line);
      if Colon > 0 then
      begin
        N := Trim(Copy(Line, 1, Colon - 1));
        if SameText(N, AName) then
        begin
          if Result <> '' then Result := Result + ', ';
          Result := Result + Trim(Copy(Line, Colon + 1, MaxInt));
        end;
      end;
    end;
end;

function StripQuotes(const S: string): string;
begin
  Result := Trim(S);
  if (Length(Result) >= 2) and (Result[1] = '"') and
     (Result[Length(Result)] = '"') then
    Result := Copy(Result, 2, Length(Result) - 2);
end;

// Parse one permessage-deflate offer/response (the part after the extension
// name). Returns False on an unknown or malformed parameter — for offers the
// caller then skips to the next offer; for responses it is fatal.
// AIsResponse tightens rules: client_max_window_bits in a response must
// carry a value.
function ParseDeflateParams(const AParams: string; AIsResponse: Boolean;
  var D: TWSDeflateParams): Boolean;
var
  Rest, Item, Name, Value: string;
  P, EQ, Bits: Integer;
  SeenServerNT, SeenClientNT, SeenServerMB, SeenClientMB: Boolean;
begin
  Result := False;
  SeenServerNT := False; SeenClientNT := False;
  SeenServerMB := False; SeenClientMB := False;
  Rest := AParams;
  while Rest <> '' do
  begin
    P := Pos(';', Rest);
    if P = 0 then
    begin
      Item := Trim(Rest);
      Rest := '';
    end
    else
    begin
      Item := Trim(Copy(Rest, 1, P - 1));
      Rest := Copy(Rest, P + 1, MaxInt);
    end;
    if Item = '' then Continue;

    EQ := Pos('=', Item);
    if EQ = 0 then
    begin
      Name := LowerCase(Item);
      Value := '';
    end
    else
    begin
      Name := LowerCase(Trim(Copy(Item, 1, EQ - 1)));
      Value := StripQuotes(Copy(Item, EQ + 1, MaxInt));
    end;

    if Name = 'server_no_context_takeover' then
    begin
      if (Value <> '') or SeenServerNT then Exit;
      SeenServerNT := True;
      D.ServerNoTakeover := True;
    end
    else if Name = 'client_no_context_takeover' then
    begin
      if (Value <> '') or SeenClientNT then Exit;
      SeenClientNT := True;
      D.ClientNoTakeover := True;
    end
    else if Name = 'server_max_window_bits' then
    begin
      // In offers and responses this always carries a value 8..15. We
      // can honor 9..15 (zlib cannot produce a true 8-bit window), so an
      // 8 makes this offer unacceptable.
      if SeenServerMB then Exit;
      SeenServerMB := True;
      if not TryStrToInt(Value, Bits) then Exit;
      if (Bits < 9) or (Bits > 15) then Exit;
      D.ServerMaxBits := Bits;
    end
    else if Name = 'client_max_window_bits' then
    begin
      if SeenClientMB then Exit;
      SeenClientMB := True;
      if Value = '' then
      begin
        // Valid only in an offer: "I could limit my window if you ask."
        if AIsResponse then Exit;
      end
      else
      begin
        if not TryStrToInt(Value, Bits) then Exit;
        if (Bits < 9) or (Bits > 15) then Exit;
        D.ClientMaxBits := Bits;
      end;
    end
    else
      Exit; // unknown parameter: offer unacceptable / response fatal
  end;
  Result := True;
end;

// Walk a Sec-WebSocket-Extensions value, take the first acceptable
// permessage-deflate offer. Comma splitting at top level is safe here:
// quoted values in this extension are integers, never contain commas.
function NegotiateDeflate(const AExtensions: string;
  var D: TWSDeflateParams): Boolean;
var
  Rest, Offer, Name, Params: string;
  P, SC: Integer;
  Trial: TWSDeflateParams;
begin
  Result := False;
  Rest := AExtensions;
  while Rest <> '' do
  begin
    P := Pos(',', Rest);
    if P = 0 then
    begin
      Offer := Trim(Rest);
      Rest := '';
    end
    else
    begin
      Offer := Trim(Copy(Rest, 1, P - 1));
      Rest := Copy(Rest, P + 1, MaxInt);
    end;
    if Offer = '' then Continue;

    SC := Pos(';', Offer);
    if SC = 0 then
    begin
      Name := LowerCase(Trim(Offer));
      Params := '';
    end
    else
    begin
      Name := LowerCase(Trim(Copy(Offer, 1, SC - 1)));
      Params := Copy(Offer, SC + 1, MaxInt);
    end;

    if Name <> 'permessage-deflate' then Continue;

    Trial.Reset;
    if ParseDeflateParams(Params, False, Trial) then
    begin
      Trial.Enabled := True;
      D := Trial;
      Exit(True);
    end;
    // unacceptable offer: try the next one
  end;
end;

// --- server role ----------------------------------------------------------


// One walk over the header block, filling slots for the names the server
// cares about. Repeated headers comma-join, mirroring HeaderValue (RFC
// 7230 list folding). Replaces seven full-request rescans on the
// connection-setup path.
const
  SRV_HDR_NAMES: array[0..6] of string = (
    'Upgrade', 'Connection', 'Sec-WebSocket-Version', 'Sec-WebSocket-Key',
    'Host', 'Sec-WebSocket-Protocol', 'Sec-WebSocket-Extensions');

type
  TSrvHeaders = array[0..6] of string;

function NameIsCI(P: PAnsiChar; L: Integer; const N: string): Boolean;
var
  I: Integer;
  A, B: AnsiChar;
begin
  if L <> Length(N) then Exit(False);
  for I := 0 to L - 1 do
  begin
    A := P[I];
    B := N[I + 1];
    if A in ['A'..'Z'] then Inc(A, 32);
    if B in ['A'..'Z'] then Inc(B, 32);
    if A <> B then Exit(False);
  end;
  Result := True;
end;

procedure CollectServerHeaders(const ARaw: RawByteString; out H: TSrvHeaders);
var
  P, PEnd, LineStart, LineEnd, Colon, NEnd, VStart, VEnd: PAnsiChar;
  K: Integer;
  V: string;
begin
  for K := 0 to High(H) do H[K] := '';
  P := PAnsiChar(ARaw);
  PEnd := P + Length(ARaw);
  // skip the request line
  while (P < PEnd) and (P^ <> #10) do Inc(P);
  if P < PEnd then Inc(P);
  while P < PEnd do
  begin
    LineStart := P;
    while (P < PEnd) and (P^ <> #10) do Inc(P);
    LineEnd := P;
    if P < PEnd then Inc(P); // past the LF
    if (LineEnd > LineStart) and ((LineEnd - 1)^ = #13) then Dec(LineEnd);
    if LineEnd = LineStart then Continue; // blank line (end of headers)
    Colon := LineStart;
    while (Colon < LineEnd) and (Colon^ <> ':') do Inc(Colon);
    if Colon = LineEnd then Continue;
    // trim the name
    NEnd := Colon;
    while (NEnd > LineStart) and ((NEnd - 1)^ in [' ', #9]) do Dec(NEnd);
    for K := 0 to High(SRV_HDR_NAMES) do
      if NameIsCI(LineStart, NEnd - LineStart, SRV_HDR_NAMES[K]) then
      begin
        VStart := Colon + 1;
        while (VStart < LineEnd) and (VStart^ in [' ', #9]) do Inc(VStart);
        VEnd := LineEnd;
        while (VEnd > VStart) and ((VEnd - 1)^ in [' ', #9]) do Dec(VEnd);
        SetString(V, VStart, VEnd - VStart);
        if H[K] = '' then
          H[K] := V
        else
          H[K] := H[K] + ', ' + V;
        Break;
      end;
  end;
end;

function ServerParseRequest(const ARaw: RawByteString; AAllowDeflate: Boolean;
  out AHS: TWSServerHandshake): Boolean;
var
  EOL, SP1, SP2: Integer;
  RequestLine, Method: RawByteString;
  H: TSrvHeaders;
begin
  Result := False;
  AHS := Default(TWSServerHandshake);
  AHS.Deflate.Reset;
  CollectServerHeaders(ARaw, H);

  EOL := Pos(#13#10, ARaw);
  if EOL = 0 then begin AHS.Failure := 'malformed request line'; Exit; end;
  RequestLine := Copy(ARaw, 1, EOL - 1);

  SP1 := Pos(' ', RequestLine);
  SP2 := 0;
  if SP1 > 0 then SP2 := Pos(' ', RequestLine, SP1 + 1);
  if (SP1 = 0) or (SP2 = 0) then
  begin
    AHS.Failure := 'malformed request line';
    Exit;
  end;
  Method := Copy(RequestLine, 1, SP1 - 1);
  AHS.Path := Copy(RequestLine, SP1 + 1, SP2 - SP1 - 1);

  if not SameText(Method, 'GET') then
  begin
    AHS.Failure := 'method must be GET';
    Exit;
  end;

  if not TokenListHas(H[0], 'websocket') then
  begin
    AHS.Failure := 'missing Upgrade: websocket';
    Exit;
  end;
  if not TokenListHas(H[1], 'Upgrade') then
  begin
    AHS.Failure := 'missing Connection: Upgrade';
    Exit;
  end;

  AHS.Version := StrToIntDef(H[2], -1);
  if AHS.Version <> 13 then
  begin
    AHS.Failure := 'unsupported version';
    Exit;
  end;

  AHS.Key := H[3];
  // 16 random bytes, base64: exactly 24 chars ending in '=='.
  if (Length(AHS.Key) <> 24) then
  begin
    AHS.Failure := 'bad Sec-WebSocket-Key';
    Exit;
  end;

  AHS.Host := H[4];
  AHS.Protocols := H[5];

  if AAllowDeflate then
    NegotiateDeflate(H[6], AHS.Deflate);

  Result := True;
end;

function ServerBuildResponse(const AHS: TWSServerHandshake): RawByteString;
var
  B: TWSStrBuilder;
begin
  B.Len := 0;
  B.App('HTTP/1.1 101 Switching Protocols'#13#10 +
    'Upgrade: websocket'#13#10 +
    'Connection: Upgrade'#13#10 +
    'Sec-WebSocket-Accept: ');
  B.App(ComputeAccept(AHS.Key));
  B.App(#13#10);
  if AHS.Deflate.Enabled then
  begin
    B.App('Sec-WebSocket-Extensions: permessage-deflate');
    if AHS.Deflate.ServerNoTakeover then
      B.App('; server_no_context_takeover');
    if AHS.Deflate.ClientNoTakeover then
      B.App('; client_no_context_takeover');
    // Echo server_max_window_bits only when the client constrained it;
    // 15 is the default so a silent 15 needs no parameter.
    if AHS.Deflate.ServerMaxBits < 15 then
    begin
      B.App('; server_max_window_bits=');
      B.App(IntToStr(AHS.Deflate.ServerMaxBits));
    end;
    B.App(#13#10);
  end;
  B.App(#13#10);
  Result := B.Done;
end;

function ServerBuildReject(ACode: Integer; const AReason: string): RawByteString;
var
  StatusText: string;
  B: TWSStrBuilder;
begin
  case ACode of
    400: StatusText := 'Bad Request';
    426: StatusText := 'Upgrade Required';
  else
    StatusText := 'Error';
  end;
  B.Len := 0;
  B.App('HTTP/1.1 ');
  B.App(IntToStr(ACode));
  B.App(' ');
  B.App(StatusText);
  B.App(#13#10'Connection: close'#13#10);
  if ACode = 426 then
    B.App('Sec-WebSocket-Version: 13'#13#10);
  B.App('Content-Length: ');
  B.App(IntToStr(Length(AReason)));
  B.App(#13#10'Content-Type: text/plain'#13#10#13#10);
  B.App(AReason);
  Result := B.Done;
end;

// --- client role ----------------------------------------------------------

var
  GRandInit: Boolean = False;

procedure WSRandomBytes(P: PByte; N: Integer);
var
  F: file of Byte;
  Got: Integer;
begin
  {$ifdef UNIX}
  AssignFile(F, '/dev/urandom');
  {$I-} System.Reset(F); {$I+}
  if IOResult = 0 then
  begin
    BlockRead(F, P^, N, Got);
    CloseFile(F);
    if Got = N then Exit;
  end;
  {$endif}
  if not GRandInit then
  begin
    Randomize;
    GRandInit := True;
  end;
  while N > 0 do
  begin
    P^ := Byte(Random(256));
    Inc(P);
    Dec(N);
  end;
end;

function ClientGenerateKey: string;
var
  Raw: array[0..15] of Byte;
begin
  WSRandomBytes(@Raw[0], 16);
  Result := Base64Encode(@Raw[0], 16);
end;

function ClientBuildRequest(const AHost, APath, AKey: string;
  AOfferDeflate: Boolean): string;
var
  B: TWSStrBuilder;
begin
  B.Len := 0;
  B.App('GET ');
  B.App(APath);
  B.App(' HTTP/1.1'#13#10'Host: ');
  B.App(AHost);
  B.App(#13#10'Upgrade: websocket'#13#10 +
    'Connection: Upgrade'#13#10 +
    'Sec-WebSocket-Key: ');
  B.App(AKey);
  B.App(#13#10'Sec-WebSocket-Version: 13'#13#10);
  if AOfferDeflate then
    B.App('Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits'#13#10);
  B.App(#13#10);
  Result := B.Done;
end;

function ClientParseResponse(const ARaw, AKey: string;
  AOfferedDeflate: Boolean;
  out ADeflate: TWSDeflateParams; out AErr: string): Boolean;
var
  EOL, SC: Integer;
  StatusLine, Ext, Name, Params: string;
begin
  Result := False;
  ADeflate.Reset;
  AErr := '';

  EOL := Pos(#13#10, ARaw);
  if EOL = 0 then begin AErr := 'malformed status line'; Exit; end;
  StatusLine := Copy(ARaw, 1, EOL - 1);
  if Pos(' 101 ', StatusLine) = 0 then
  begin
    AErr := 'expected 101, got: ' + StatusLine;
    Exit;
  end;

  if not TokenListHas(HeaderValue(ARaw, 'Upgrade'), 'websocket') then
  begin
    AErr := 'missing Upgrade: websocket';
    Exit;
  end;
  if not TokenListHas(HeaderValue(ARaw, 'Connection'), 'Upgrade') then
  begin
    AErr := 'missing Connection: Upgrade';
    Exit;
  end;
  if Trim(HeaderValue(ARaw, 'Sec-WebSocket-Accept')) <> ComputeAccept(AKey) then
  begin
    AErr := 'Sec-WebSocket-Accept mismatch';
    Exit;
  end;

  Ext := Trim(HeaderValue(ARaw, 'Sec-WebSocket-Extensions'));
  if Ext <> '' then
  begin
    if not AOfferedDeflate then
    begin
      AErr := 'server selected unoffered extension: ' + Ext;
      Exit;
    end;
    SC := Pos(';', Ext);
    if SC = 0 then
    begin
      Name := LowerCase(Trim(Ext));
      Params := '';
    end
    else
    begin
      Name := LowerCase(Trim(Copy(Ext, 1, SC - 1)));
      Params := Copy(Ext, SC + 1, MaxInt);
    end;
    if Name <> 'permessage-deflate' then
    begin
      AErr := 'server selected unoffered extension: ' + Name;
      Exit;
    end;
    if not ParseDeflateParams(Params, True, ADeflate) then
    begin
      AErr := 'bad permessage-deflate response params';
      Exit;
    end;
    ADeflate.Enabled := True;
  end;

  Result := True;
end;

end.
