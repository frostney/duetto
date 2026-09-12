{ WS.Handshake.Test — the §4.2.2 ComputeAccept vector, the §1.2 sample
  request parsed field-by-field, header case/token-list tolerance, the
  rejection matrix (method, version, key shape, missing headers), client
  key generation entropy shape, and a full client<->server round trip:
  ClientBuildRequest -> ServerParseRequest -> ServerBuildResponse ->
  ClientParseResponse, with the permessage-deflate negotiation matrix
  (plain offer, parameterised offers, junk offer recovery, unknown
  extensions ignored, unoffered server selection rejected). Plus the
  request-kind classification behind TWSServer.OnPlainRequest: body-less
  GET/HEAD without Upgrade classify wrkPlain, upgrade attempts (valid or
  broken) stay wrkUpgrade, bodies and malformed noise fall to wrkOther —
  with the pre-hook refusal strings untouched. The body-less gate is
  presence-based and fail-closed (empty values, header-name case,
  duplicates, identity transfer-codings and obs-fold all disqualify),
  the header walk stops dead at the blank line so a pipelined follow-up
  can neither contribute headers nor demote the request ahead of it, and
  the plain path requires a known HTTP version. Plus the raw-block
  helpers the hook contract exposes: HeaderValue's list join and
  blank-line stop, and the byte-exact standard refusal. Plus what
  TWSServer.OnUpgradeRequest adds: the Origin header parsed alongside
  Host (empty when absent) and the byte-exact 403 refusal. }

program WS.Handshake.Test;

{$I Shared.inc}

uses
  SysUtils,

  base64,
  TestingPascalLibrary,
  WS.Handshake;

const
  CRLF = #13#10;
  RFCRequest =
    'GET /chat HTTP/1.1' + CRLF +
    'Host: server.example.com' + CRLF +
    'Upgrade: websocket' + CRLF +
    'Connection: Upgrade' + CRLF +
    'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' + CRLF +
    'Origin: http://example.com' + CRLF +
    'Sec-WebSocket-Protocol: chat, superchat' + CRLF +
    'Sec-WebSocket-Version: 13' + CRLF + CRLF;

type
  TAcceptVector = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestRFCAccept;
  end;

  TServerParse = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestRFCSample;
    procedure TestCaseAndTokenLists;
    procedure TestRejectionMatrix;
    procedure TestFindEnd;
  end;

  TClientRole = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestKeyShape;
    procedure TestFullRoundTrip;
    procedure TestAcceptMismatch;
    procedure TestNon101;
    procedure TestUnofferedExtensionRejected;
  end;

  TPlainClassification = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestPlainGet;
    procedure TestPlainHead;
    procedure TestPostWithBody;
    procedure TestContentLengthZeroExcluded;
    procedure TestChunkedExcluded;
    procedure TestMalformedIsOther;
    procedure TestBrokenUpgradeStaysUpgrade;
    procedure TestValidUpgradeKind;
    procedure TestPipelinedHeadersNotFolded;
    procedure TestPipelinedBodyDoesNotDemote;
    procedure TestEmptyValuedBodyHeadersExcluded;
    procedure TestObsFoldExcluded;
    procedure TestGateIsHeaderNameCaseInsensitive;
    procedure TestDuplicateContentLengthZeroExcluded;
    procedure TestTransferEncodingIdentityExcluded;
    procedure TestUpgradeWithBodyStaysUpgrade;
    procedure TestMalformedLineWithUpgradeIsOther;
    procedure TestJunkHttpVersionIsOther;
    procedure TestHttp10IsPlain;
    procedure TestAbsoluteFormTargetVerbatim;
    procedure TestForeignUpgradeTokenIsPlain;
    procedure TestConnectionUpgradeAloneIsPlain;
  end;

  TRawBlockHelpers = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestHeaderValueStopsAtBlankLine;
    procedure TestHeaderValueJoinsRepeats;
    procedure TestRejectGoldenBytes;
    procedure TestOriginParsed;
    procedure TestOriginAbsent;
    procedure TestForbiddenGoldenBytes;
  end;

  TDeflateNegotiation = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestPlainOffer;
    procedure TestParameterisedOffer;
    procedure TestJunkOfferFallsToNext;
    procedure TestUnknownExtensionIgnored;
    procedure TestDisabledWhenServerForbids;
  end;

function MakeRequest(const AExtensions: string): string;
begin
  Result :=
    'GET / HTTP/1.1' + CRLF +
    'Host: x' + CRLF +
    'Upgrade: websocket' + CRLF +
    'Connection: Upgrade' + CRLF +
    'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' + CRLF +
    'Sec-WebSocket-Version: 13' + CRLF;
  if AExtensions <> '' then
    Result := Result + 'Sec-WebSocket-Extensions: ' + AExtensions + CRLF;
  Result := Result + CRLF;
end;

{ ───────── §4.2.2 ───────── }

procedure TAcceptVector.TestRFCAccept;
begin
  Expect<string>(ComputeAccept('dGhlIHNhbXBsZSBub25jZQ=='))
    .ToBe('s3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
end;

{ ───────── server parse ───────── }

procedure TServerParse.TestRFCSample;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(RFCRequest, False, HS)).ToBe(True);
  Expect<string>(HS.Path).ToBe('/chat');
  Expect<string>(HS.Host).ToBe('server.example.com');
  Expect<string>(HS.Key).ToBe('dGhlIHNhbXBsZSBub25jZQ==');
  Expect<Integer>(HS.Version).ToBe(13);
  Expect<string>(HS.Protocols).ToBe('chat, superchat');
  Expect<string>(HS.Origin).ToBe('http://example.com');
  Expect<Boolean>(HS.Deflate.Enabled).ToBe(False);
end;

procedure TServerParse.TestCaseAndTokenLists;
var
  HS: TWSServerHandshake;
  Req: string;
begin
  // RFC 7230: header names case-insensitive; Connection is a token list
  // and browsers really do send "keep-alive, Upgrade".
  Req :=
    'GET / HTTP/1.1' + CRLF +
    'host: X' + CRLF +
    'UPGRADE: WebSocket' + CRLF +
    'connection: keep-alive, Upgrade' + CRLF +
    'SEC-WEBSOCKET-KEY: dGhlIHNhbXBsZSBub25jZQ==' + CRLF +
    'sec-websocket-version: 13' + CRLF + CRLF;
  Expect<Boolean>(ServerParseRequest(Req, False, HS)).ToBe(True);
end;

procedure TServerParse.TestRejectionMatrix;
var
  HS: TWSServerHandshake;

  function Drop(const ALine: string): string;
  begin
    Result := StringReplace(RFCRequest, ALine + CRLF, '', []);
  end;

begin
  Expect<Boolean>(ServerParseRequest(
    StringReplace(RFCRequest, 'GET', 'POST', []), False, HS)).ToBe(False);
  Expect<string>(HS.Failure).ToBe('method must be GET');

  Expect<Boolean>(ServerParseRequest(
    Drop('Upgrade: websocket'), False, HS)).ToBe(False);

  Expect<Boolean>(ServerParseRequest(
    Drop('Connection: Upgrade'), False, HS)).ToBe(False);

  Expect<Boolean>(ServerParseRequest(
    StringReplace(RFCRequest, 'Version: 13', 'Version: 8', []),
    False, HS)).ToBe(False);
  Expect<string>(HS.Failure).ToBe('unsupported version');

  Expect<Boolean>(ServerParseRequest(
    Drop('Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='), False, HS)).ToBe(False);

  // Key must decode to exactly 16 bytes (§4.2.1 item 5).
  Expect<Boolean>(ServerParseRequest(
    StringReplace(RFCRequest, 'dGhlIHNhbXBsZSBub25jZQ==', 'c2hvcnQ=', []),
    False, HS)).ToBe(False);
end;

procedure TServerParse.TestFindEnd;
var
  S: AnsiString;
begin
  S := 'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF;
  Expect<Integer>(HandshakeFindEnd(PByte(PAnsiChar(S)), Length(S))).ToBe(0);
  S := S + CRLF;
  Expect<Integer>(HandshakeFindEnd(PByte(PAnsiChar(S)), Length(S))).ToBe(Length(S));
  S := S + 'EXTRA BYTES AFTER';
  Expect<Integer>(HandshakeFindEnd(PByte(PAnsiChar(S)), Length(S)))
    .ToBe(Length(S) - Length('EXTRA BYTES AFTER'));
end;

{ ───────── client role ───────── }

procedure TClientRole.TestKeyShape;
var
  K1, K2: string;
begin
  K1 := ClientGenerateKey;
  K2 := ClientGenerateKey;
  Expect<Boolean>(K1 = K2).ToBe(False);
  Expect<Integer>(Length(DecodeStringBase64(K1))).ToBe(16);
end;

procedure TClientRole.TestFullRoundTrip;
var
  Key, Req, Resp, Err: string;
  HS: TWSServerHandshake;
  D: TWSDeflateParams;
begin
  Key := ClientGenerateKey;
  Req := ClientBuildRequest('localhost:9001', '/echo', Key, True);
  Expect<Boolean>(ServerParseRequest(Req, True, HS)).ToBe(True);
  Expect<string>(HS.Path).ToBe('/echo');
  Expect<Boolean>(HS.Deflate.Enabled).ToBe(True);
  Resp := ServerBuildResponse(HS);
  Expect<Boolean>(ClientParseResponse(Resp, Key, True, D, Err)).ToBe(True);
  Expect<string>(Err).ToBe('');
  Expect<Boolean>(D.Enabled).ToBe(True);
end;

procedure TClientRole.TestAcceptMismatch;
var
  Key, Req, Resp, Err: string;
  HS: TWSServerHandshake;
  D: TWSDeflateParams;
begin
  Key := ClientGenerateKey;
  Req := ClientBuildRequest('x', '/', Key, False);
  Expect<Boolean>(ServerParseRequest(Req, False, HS)).ToBe(True);
  Resp := ServerBuildResponse(HS);
  Expect<Boolean>(ClientParseResponse(Resp, ClientGenerateKey, False, D, Err)).ToBe(False);
  Expect<string>(Err).ToBe('Sec-WebSocket-Accept mismatch');
end;

procedure TClientRole.TestNon101;
var
  D: TWSDeflateParams;
  Err: string;
begin
  Expect<Boolean>(ClientParseResponse(
    'HTTP/1.1 403 Forbidden' + CRLF + CRLF, 'k', False, D, Err)).ToBe(False);
end;

procedure TClientRole.TestUnofferedExtensionRejected;
var
  Key, Req, Resp, Err: string;
  HS: TWSServerHandshake;
  D: TWSDeflateParams;
begin
  Key := ClientGenerateKey;
  // We did NOT offer deflate; a server selecting it anyway is a §4.1
  // failure the client must catch.
  Req := ClientBuildRequest('x', '/', Key, False);
  Expect<Boolean>(ServerParseRequest(Req, True, HS)).ToBe(True);
  Expect<Boolean>(HS.Deflate.Enabled).ToBe(False);
  HS.Deflate.Enabled := True; // malicious/buggy server
  Resp := ServerBuildResponse(HS);
  Expect<Boolean>(ClientParseResponse(Resp, Key, False, D, Err)).ToBe(False);
end;

{ ───────── plain-request classification ───────── }

procedure TPlainClassification.TestPlainGet;
var
  HS: TWSServerHandshake;
  Req: string;
begin
  Req :=
    'GET /index.html HTTP/1.1' + CRLF +
    'Host: server.example.com' + CRLF +
    'Accept: text/html' + CRLF + CRLF;
  Expect<Boolean>(ServerParseRequest(Req, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkPlain);
  Expect<string>(HS.Method).ToBe('GET');
  Expect<string>(HS.Path).ToBe('/index.html');
  Expect<string>(HS.Host).ToBe('server.example.com');
  // Refusal diagnostics unchanged from the pre-hook parser.
  Expect<string>(HS.Failure).ToBe('missing Upgrade: websocket');
  // The exported HeaderValue covers headers the parser has no slot for.
  Expect<string>(HeaderValue(Req, 'accept')).ToBe('text/html');
end;

procedure TPlainClassification.TestPlainHead;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'HEAD / HTTP/1.1' + CRLF + 'Host: x' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkPlain);
  Expect<string>(HS.Method).ToBe('HEAD');
  Expect<string>(HS.Failure).ToBe('method must be GET');
end;

procedure TPlainClassification.TestPostWithBody;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'POST /submit HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'Content-Length: 5' + CRLF + CRLF + 'hello', False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
end;

procedure TPlainClassification.TestContentLengthZeroExcluded;
var
  HS: TWSServerHandshake;
begin
  // Scope is body-less by header shape: any Content-Length, even 0,
  // keeps the standard refusal.
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'Content-Length: 0' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
end;

procedure TPlainClassification.TestChunkedExcluded;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'Transfer-Encoding: chunked' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
end;

procedure TPlainClassification.TestMalformedIsOther;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'NOISE' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
  Expect<string>(HS.Failure).ToBe('malformed request line');
end;

procedure TPlainClassification.TestBrokenUpgradeStaysUpgrade;
var
  HS: TWSServerHandshake;
begin
  // An upgrade attempt that fails validation must never reach the
  // plain-request hook.
  Expect<Boolean>(ServerParseRequest(
    StringReplace(RFCRequest, 'Version: 13', 'Version: 8', []),
    False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkUpgrade);
end;

procedure TPlainClassification.TestValidUpgradeKind;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(RFCRequest, False, HS)).ToBe(True);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkUpgrade);
  Expect<string>(HS.Method).ToBe('GET');
end;

// The session layer hands the parser one header block, but the parser
// must be sound whatever it is given: the walk stops at the blank line,
// so a pipelined second request contributes nothing to the first.
procedure TPlainClassification.TestPipelinedHeadersNotFolded;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET /one HTTP/1.1' + CRLF + 'Host: a' + CRLF + CRLF +
    'GET /two HTTP/1.1' + CRLF + 'Host: b' + CRLF + CRLF,
    False, HS)).ToBe(False);
  // Not 'a, b': the second request's Host is not this request's.
  Expect<string>(HS.Host).ToBe('a');
  Expect<string>(HS.Path).ToBe('/one');
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkPlain);
end;

// The other direction of the same bug: a pipelined follow-up carrying a
// body must not demote the body-less request in front of it.
procedure TPlainClassification.TestPipelinedBodyDoesNotDemote;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET /one HTTP/1.1' + CRLF + 'Host: a' + CRLF + CRLF +
    'POST /two HTTP/1.1' + CRLF + 'Host: a' + CRLF +
    'Content-Length: 5' + CRLF + CRLF + 'hello',
    False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkPlain);
end;

// The gate keys off the header NAME, so an empty value is still a
// Content-Length and still disqualifies.
procedure TPlainClassification.TestEmptyValuedBodyHeadersExcluded;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'Content-Length:' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);

  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'Transfer-Encoding: ' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
end;

// RFC 7230 §3.2.4 obs-fold is deprecated and ambiguous to split; a
// folded Content-Length is the smuggling shape the gate exists to stop,
// so any continuation line in the block fails closed.
procedure TPlainClassification.TestObsFoldExcluded;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'X-Note: first' + CRLF + ' continued' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);

  // ... including a HTAB continuation.
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'X-Note: first' + CRLF + #9'continued' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
end;

procedure TPlainClassification.TestGateIsHeaderNameCaseInsensitive;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'content-length: 0' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);

  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'TRANSFER-ENCODING: chunked' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
end;

procedure TPlainClassification.TestDuplicateContentLengthZeroExcluded;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'Content-Length: 0' + CRLF + 'Content-Length: 0' + CRLF + CRLF,
    False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
end;

// Presence, not value: 'identity' advertises no body at all and still
// disqualifies, because the gate never inspects the value.
procedure TPlainClassification.TestTransferEncodingIdentityExcluded;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'Transfer-Encoding: identity' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
end;

// The body-less gate guards the plain path only — an upgrade attempt is
// classified by its Upgrade header and reaches the WebSocket path
// whatever else it advertises.
procedure TPlainClassification.TestUpgradeWithBodyStaysUpgrade;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    StringReplace(RFCRequest, 'Host: server.example.com' + CRLF,
      'Host: server.example.com' + CRLF + 'Content-Length: 5' + CRLF, []),
    False, HS)).ToBe(True);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkUpgrade);
end;

// A parseable request line is the precondition for any kind but
// wrkOther: noise with an Upgrade header is still noise.
procedure TPlainClassification.TestMalformedLineWithUpgradeIsOther;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'NOISE' + CRLF + 'Upgrade: websocket' + CRLF +
    'Connection: Upgrade' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
  Expect<string>(HS.Failure).ToBe('malformed request line');
end;

procedure TPlainClassification.TestJunkHttpVersionIsOther;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/9.9' + CRLF + 'Host: x' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);

  Expect<Boolean>(ServerParseRequest(
    'GET / RTSP/1.0' + CRLF + 'Host: x' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkOther);
end;

procedure TPlainClassification.TestHttp10IsPlain;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET /x HTTP/1.0' + CRLF + 'Host: x' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkPlain);
end;

// RFC 7230 §5.3.2 absolute-form: the target lands in Path verbatim, so
// hooks matching on Path have to expect it (documented on the event).
procedure TPlainClassification.TestAbsoluteFormTargetVerbatim;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET http://server.example.com/x HTTP/1.1' + CRLF +
    'Host: server.example.com' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkPlain);
  Expect<string>(HS.Path).ToBe('http://server.example.com/x');
end;

// An upgrade to something that is not WebSocket is not our upgrade: it
// is a plain request we may answer (and then close).
procedure TPlainClassification.TestForeignUpgradeTokenIsPlain;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF + 'Upgrade: h2c' + CRLF +
    'Connection: Upgrade' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkPlain);
end;

procedure TPlainClassification.TestConnectionUpgradeAloneIsPlain;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    'GET / HTTP/1.1' + CRLF + 'Host: x' + CRLF +
    'Connection: Upgrade' + CRLF + CRLF, False, HS)).ToBe(False);
  Expect<TWSRequestKind>(HS.Kind).ToBe(wrkPlain);
end;

{ ───────── raw-block helpers on the hook contract ───────── }

// OnPlainRequest hands the hook one header block and points it at
// HeaderValue; that helper must not read past the blank line either.
procedure TRawBlockHelpers.TestHeaderValueStopsAtBlankLine;
var
  Raw: string;
begin
  Raw :=
    'GET /one HTTP/1.1' + CRLF + 'X-Tag: first' + CRLF + CRLF +
    'GET /two HTTP/1.1' + CRLF + 'X-Tag: second' + CRLF + CRLF;
  Expect<string>(HeaderValue(Raw, 'X-Tag')).ToBe('first');
  // A body is equally out of bounds, even one that looks like a header.
  Raw :=
    'POST / HTTP/1.1' + CRLF + 'Content-Length: 14' + CRLF + CRLF +
    'X-Tag: inbody' + CRLF;
  Expect<string>(HeaderValue(Raw, 'X-Tag')).ToBe('');
end;

// RFC 7230 list semantics: repeats inside one block join with ', '.
procedure TRawBlockHelpers.TestHeaderValueJoinsRepeats;
var
  Raw: string;
begin
  Raw :=
    'GET / HTTP/1.1' + CRLF + 'Accept: text/html' + CRLF +
    'accept: text/plain' + CRLF + CRLF;
  Expect<string>(HeaderValue(Raw, 'Accept')).ToBe('text/html, text/plain');
  Expect<string>(HeaderValue(Raw, 'X-Absent')).ToBe('');
end;

// The standard refusal is what every path falls back to — an unset
// hook, a False return, a True with an empty body, a raising hook. Pin
// it byte for byte so those paths stay indistinguishable on the wire.
procedure TRawBlockHelpers.TestRejectGoldenBytes;
begin
  Expect<string>(string(ServerBuildReject(400, 'nope'))).ToBe(
    'HTTP/1.1 400 Bad Request' + CRLF +
    'Connection: close' + CRLF +
    'Content-Length: 4' + CRLF +
    'Content-Type: text/plain' + CRLF + CRLF +
    'nope');
end;

// Origin rides the same single header walk as Host: case-insensitive
// name, value trimmed, verbatim otherwise (OnUpgradeRequest decides
// what it means).
procedure TRawBlockHelpers.TestOriginParsed;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(RFCRequest, False, HS)).ToBe(True);
  Expect<string>(HS.Origin).ToBe('http://example.com');
  Expect<Boolean>(ServerParseRequest(
    StringReplace(RFCRequest, 'Origin: http://example.com',
      'origin:   https://App.Example:8443  ', []), False, HS)).ToBe(True);
  Expect<string>(HS.Origin).ToBe('https://App.Example:8443');
end;

// No Origin header (non-browser clients) is the empty string, not a
// failure: whether that is acceptable is the hook's call.
procedure TRawBlockHelpers.TestOriginAbsent;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(MakeRequest(''), False, HS)).ToBe(True);
  Expect<string>(HS.Origin).ToBe('');
end;

// OnUpgradeRequest's refusal on the wire: pinned byte for byte so a
// False return and a raising hook stay indistinguishable to the client.
procedure TRawBlockHelpers.TestForbiddenGoldenBytes;
begin
  Expect<string>(string(ServerBuildReject(403, 'origin not allowed'))).ToBe(
    'HTTP/1.1 403 Forbidden' + CRLF +
    'Connection: close' + CRLF +
    'Content-Length: 18' + CRLF +
    'Content-Type: text/plain' + CRLF + CRLF +
    'origin not allowed');
end;

{ ───────── deflate negotiation ───────── }

procedure TDeflateNegotiation.TestPlainOffer;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    MakeRequest('permessage-deflate'), True, HS)).ToBe(True);
  Expect<Boolean>(HS.Deflate.Enabled).ToBe(True);
  Expect<Integer>(HS.Deflate.ServerMaxBits).ToBe(15);
  Expect<Integer>(HS.Deflate.ClientMaxBits).ToBe(15);
end;

procedure TDeflateNegotiation.TestParameterisedOffer;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    MakeRequest('permessage-deflate; client_max_window_bits; ' +
      'server_max_window_bits=10; server_no_context_takeover'),
    True, HS)).ToBe(True);
  Expect<Boolean>(HS.Deflate.Enabled).ToBe(True);
  Expect<Integer>(HS.Deflate.ServerMaxBits).ToBe(10);
  Expect<Boolean>(HS.Deflate.ServerNoTakeover).ToBe(True);
end;

procedure TDeflateNegotiation.TestJunkOfferFallsToNext;
var
  HS: TWSServerHandshake;
begin
  // First offer has an invalid parameter value; §7's "decline this offer,
  // consider the next" applies.
  Expect<Boolean>(ServerParseRequest(
    MakeRequest('permessage-deflate; server_max_window_bits=99, ' +
      'permessage-deflate'),
    True, HS)).ToBe(True);
  Expect<Boolean>(HS.Deflate.Enabled).ToBe(True);
  Expect<Integer>(HS.Deflate.ServerMaxBits).ToBe(15);
end;

procedure TDeflateNegotiation.TestUnknownExtensionIgnored;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    MakeRequest('x-webkit-frobnicate; level=11, permessage-deflate'),
    True, HS)).ToBe(True);
  Expect<Boolean>(HS.Deflate.Enabled).ToBe(True);
end;

procedure TDeflateNegotiation.TestDisabledWhenServerForbids;
var
  HS: TWSServerHandshake;
begin
  Expect<Boolean>(ServerParseRequest(
    MakeRequest('permessage-deflate'), False, HS)).ToBe(True);
  Expect<Boolean>(HS.Deflate.Enabled).ToBe(False);
end;

procedure TAcceptVector.SetupTests;
begin
  Test('RFC 6455 §4.2.2 accept vector',          TestRFCAccept);
end;

procedure TServerParse.SetupTests;
begin
  Test('§1.2 sample request, field by field',    TestRFCSample);
  Test('header case + Connection token list',    TestCaseAndTokenLists);
  Test('rejection matrix',                       TestRejectionMatrix);
  Test('HandshakeFindEnd partial/exact/overrun', TestFindEnd);
end;

procedure TClientRole.SetupTests;
begin
  Test('generated key: 16 bytes, non-repeating', TestKeyShape);
  Test('client<->server full round trip',        TestFullRoundTrip);
  Test('accept mismatch detected',               TestAcceptMismatch);
  Test('non-101 status rejected',                TestNon101);
  Test('unoffered server extension rejected',    TestUnofferedExtensionRejected);
end;

procedure TPlainClassification.SetupTests;
begin
  Test('body-less GET classifies wrkPlain',      TestPlainGet);
  Test('HEAD classifies wrkPlain',               TestPlainHead);
  Test('POST with body is wrkOther',             TestPostWithBody);
  Test('Content-Length: 0 excluded',             TestContentLengthZeroExcluded);
  Test('Transfer-Encoding excluded',             TestChunkedExcluded);
  Test('malformed request line is wrkOther',     TestMalformedIsOther);
  Test('broken upgrade attempt stays wrkUpgrade', TestBrokenUpgradeStaysUpgrade);
  Test('valid upgrade classifies wrkUpgrade',    TestValidUpgradeKind);
  Test('pipelined request folds no headers in',  TestPipelinedHeadersNotFolded);
  Test('pipelined body does not demote',         TestPipelinedBodyDoesNotDemote);
  Test('empty-valued body headers excluded',     TestEmptyValuedBodyHeadersExcluded);
  Test('obs-fold anywhere excluded',             TestObsFoldExcluded);
  Test('gate is header-name case-insensitive',   TestGateIsHeaderNameCaseInsensitive);
  Test('duplicate Content-Length: 0 excluded',   TestDuplicateContentLengthZeroExcluded);
  Test('Transfer-Encoding: identity excluded',   TestTransferEncodingIdentityExcluded);
  Test('gate not applied to upgrades',           TestUpgradeWithBodyStaysUpgrade);
  Test('malformed line + Upgrade is wrkOther',   TestMalformedLineWithUpgradeIsOther);
  Test('junk HTTP version is wrkOther',          TestJunkHttpVersionIsOther);
  Test('HTTP/1.0 GET classifies wrkPlain',       TestHttp10IsPlain);
  Test('absolute-form target kept verbatim',     TestAbsoluteFormTargetVerbatim);
  Test('foreign Upgrade token is wrkPlain',      TestForeignUpgradeTokenIsPlain);
  Test('Connection: Upgrade alone is wrkPlain',  TestConnectionUpgradeAloneIsPlain);
end;

procedure TRawBlockHelpers.SetupTests;
begin
  Test('HeaderValue stops at the blank line',    TestHeaderValueStopsAtBlankLine);
  Test('HeaderValue joins repeats with '', ''',  TestHeaderValueJoinsRepeats);
  Test('standard refusal is byte-identical',     TestRejectGoldenBytes);
  Test('Origin parsed alongside Host',          TestOriginParsed);
  Test('absent Origin is the empty string',      TestOriginAbsent);
  Test('403 refusal is byte-identical',          TestForbiddenGoldenBytes);
end;

procedure TDeflateNegotiation.SetupTests;
begin
  Test('plain permessage-deflate offer',         TestPlainOffer);
  Test('parameterised offer honoured',           TestParameterisedOffer);
  Test('invalid offer falls through to next',    TestJunkOfferFallsToNext);
  Test('unknown extension ignored',              TestUnknownExtensionIgnored);
  Test('server policy can refuse deflate',       TestDisabledWhenServerForbids);
end;

begin
  TestRunnerProgram.AddSuite(TAcceptVector.Create('Handshake: accept'));
  TestRunnerProgram.AddSuite(TServerParse.Create('Handshake: server parse'));
  TestRunnerProgram.AddSuite(TClientRole.Create('Handshake: client role'));
  TestRunnerProgram.AddSuite(TPlainClassification.Create('Handshake: plain classification'));
  TestRunnerProgram.AddSuite(TRawBlockHelpers.Create('Handshake: raw-block helpers'));
  TestRunnerProgram.AddSuite(TDeflateNegotiation.Create('Handshake: deflate negotiation'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
