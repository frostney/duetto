{ WS.Handshake.Test — the §4.2.2 ComputeAccept vector, the §1.2 sample
  request parsed field-by-field, header case/token-list tolerance, the
  rejection matrix (method, version, key shape, missing headers), client
  key generation entropy shape, and a full client<->server round trip:
  ClientBuildRequest -> ServerParseRequest -> ServerBuildResponse ->
  ClientParseResponse, with the permessage-deflate negotiation matrix
  (plain offer, parameterised offers, junk offer recovery, unknown
  extensions ignored, unoffered server selection rejected). }

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
  TestRunnerProgram.AddSuite(TDeflateNegotiation.Create('Handshake: deflate negotiation'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
