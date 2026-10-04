{ WS.Url.Test — the client's ws:// / wss:// parser (WSParseUrl): RFC 3986
  authority forms (registered names, bracketed IPv6 literals, userinfo
  dropped, port 1..65535 or empty), the case-insensitive scheme, the
  RFC 6455 §3 resource name (a query without a path gets '/'), the §4.1
  Host value (port only when it is not the scheme's default, IPv6 kept
  bracketed), and rejection tables: fragments (§3), control characters
  and spaces that could inject header lines or split the request line,
  bad ports, bad hosts and foreign schemes. Every row is compared as one
  string naming the input, so a failure says which URL did what. }

program WS.Url.Test;

{$I Shared.inc}

uses
  SysUtils,

  TestingPascalLibrary,
  WS.Url;

type
  TUrlForms = class(TTestSuite)
  private
    procedure ExpectParsed(const AUrl, AExpected: string);
    procedure ExpectRejected(const AUrl, AError: string);
  public
    procedure SetupTests; override;
    procedure TestNames;
    procedure TestSchemeCase;
    procedure TestHostHeaderPort;
    procedure TestIPv6Literals;
    procedure TestUserinfoDropped;
    procedure TestResourceName;
    procedure TestPortRange;
    procedure TestFragmentsRejected;
    procedure TestControlCharactersRejected;
    procedure TestBadHostsRejected;
    procedure TestBadSchemesRejected;
  end;

// One line per parse: the input, then either every field or the error.
function Describe(const AUrl: string): string;
var
  U: TWSUrl;
  Err, Scheme: string;
begin
  if not WSParseUrl(AUrl, U, Err) then
    Exit(AUrl + ' -> rejected: ' + Err);
  if Err <> '' then
    Exit(AUrl + ' -> accepted with an error set: ' + Err);
  if U.Secure then Scheme := 'wss' else Scheme := 'ws';
  Result := Format('%s -> %s host=%s port=%d resource=%s header=%s',
    [AUrl, Scheme, U.Host, U.Port, U.Resource, U.HostHeader]);
  if U.IPv6Literal then Result := Result + ' ipv6';
end;

procedure TUrlForms.ExpectParsed(const AUrl, AExpected: string);
begin
  Expect<string>(Describe(AUrl)).ToBe(AUrl + ' -> ' + AExpected);
end;

procedure TUrlForms.ExpectRejected(const AUrl, AError: string);
begin
  Expect<string>(Describe(AUrl)).ToBe(AUrl + ' -> rejected: ' + AError);
end;

const
  BadPort = 'bad port in URL';
  MissingHost = 'missing host in URL';
  BadHostChar = 'invalid character in URL host';
  BadLiteral = 'bad IPv6 literal in URL';
  BadPath = 'control character or space in URL path or query';
  Fragment = 'URL fragments are not allowed (RFC 6455 section 3)';
  BadScheme = 'URL must start with ws:// or wss://';

procedure TUrlForms.TestNames;
begin
  ExpectParsed('ws://example.com/chat',
    'ws host=example.com port=80 resource=/chat header=example.com');
  ExpectParsed('wss://example.com',
    'wss host=example.com port=443 resource=/ header=example.com');
  ExpectParsed('ws://127.0.0.1:9001/',
    'ws host=127.0.0.1 port=9001 resource=/ header=127.0.0.1:9001');
  ExpectParsed('ws://my_host.local-1/a/b',
    'ws host=my_host.local-1 port=80 resource=/a/b header=my_host.local-1');
  // Percent-encoding is passed through, never decoded.
  ExpectParsed('ws://h/a%20b%23c',
    'ws host=h port=80 resource=/a%20b%23c header=h');
end;

procedure TUrlForms.TestSchemeCase;
begin
  ExpectParsed('WS://h/', 'ws host=h port=80 resource=/ header=h');
  ExpectParsed('Ws://h/', 'ws host=h port=80 resource=/ header=h');
  ExpectParsed('WSS://h/', 'wss host=h port=443 resource=/ header=h');
  ExpectParsed('wSs://h/', 'wss host=h port=443 resource=/ header=h');
end;

procedure TUrlForms.TestHostHeaderPort;
begin
  // The port is left out only when it is the default of this URL's own
  // scheme: 443 on ws:// and 80 on wss:// are not defaults.
  ExpectParsed('ws://h:80/', 'ws host=h port=80 resource=/ header=h');
  ExpectParsed('wss://h:443/', 'wss host=h port=443 resource=/ header=h');
  ExpectParsed('ws://h:443/', 'ws host=h port=443 resource=/ header=h:443');
  ExpectParsed('wss://h:80/', 'wss host=h port=80 resource=/ header=h:80');
  ExpectParsed('wss://h:8443/',
    'wss host=h port=8443 resource=/ header=h:8443');
  // An empty port is the default (RFC 3986 §3.2.3).
  ExpectParsed('ws://h:/', 'ws host=h port=80 resource=/ header=h');
  ExpectParsed('wss://h:', 'wss host=h port=443 resource=/ header=h');
end;

procedure TUrlForms.TestIPv6Literals;
begin
  ExpectParsed('ws://[::1]/',
    'ws host=::1 port=80 resource=/ header=[::1] ipv6');
  ExpectParsed('ws://[::1]:9001/',
    'ws host=::1 port=9001 resource=/ header=[::1]:9001 ipv6');
  ExpectParsed('wss://[2001:db8::7]:443/feed?x=1',
    'wss host=2001:db8::7 port=443 resource=/feed?x=1 header=[2001:db8::7] ipv6');
  ExpectParsed('ws://[::FFFF:127.0.0.1]:8080',
    'ws host=::FFFF:127.0.0.1 port=8080 resource=/ header=[::FFFF:127.0.0.1]:8080 ipv6');
  ExpectParsed('ws://[::1]?q',
    'ws host=::1 port=80 resource=/?q header=[::1] ipv6');
  ExpectParsed('ws://[::1]:/',
    'ws host=::1 port=80 resource=/ header=[::1] ipv6');
end;

procedure TUrlForms.TestUserinfoDropped;
begin
  // Never sent anywhere: not in Host, not in the resource name.
  ExpectParsed('ws://user:pass@example.com:9001/p',
    'ws host=example.com port=9001 resource=/p header=example.com:9001');
  ExpectParsed('wss://user@h', 'wss host=h port=443 resource=/ header=h');
  ExpectParsed('ws://u:p@[::1]:9/',
    'ws host=::1 port=9 resource=/ header=[::1]:9 ipv6');
  ExpectParsed('ws://:@h/', 'ws host=h port=80 resource=/ header=h');
  // The last '@' of the authority ends the userinfo; one after the
  // authority belongs to the path.
  ExpectParsed('ws://a@b@h/', 'ws host=h port=80 resource=/ header=h');
  ExpectParsed('ws://h/a@b', 'ws host=h port=80 resource=/a@b header=h');
  ExpectParsed('ws://h?a@b', 'ws host=h port=80 resource=/?a@b header=h');
end;

procedure TUrlForms.TestResourceName;
begin
  // §3: '/' when the path is empty, then the path, then '?query' when
  // the query is non-empty.
  ExpectParsed('ws://h?x=1', 'ws host=h port=80 resource=/?x=1 header=h');
  ExpectParsed('ws://h:9001?x=1',
    'ws host=h port=9001 resource=/?x=1 header=h:9001');
  ExpectParsed('ws://h/p?x=1&y=2',
    'ws host=h port=80 resource=/p?x=1&y=2 header=h');
  ExpectParsed('ws://h/p?', 'ws host=h port=80 resource=/p header=h');
  ExpectParsed('ws://h?', 'ws host=h port=80 resource=/ header=h');
  ExpectParsed('ws://h/p??', 'ws host=h port=80 resource=/p?? header=h');
  ExpectParsed('ws://h/?a=/b:c', 'ws host=h port=80 resource=/?a=/b:c header=h');
end;

procedure TUrlForms.TestPortRange;
const
  Rejected: array[0..9] of string = (
    'ws://h:0/', 'ws://h:65536/', 'ws://h:99999999999999999999/',
    'ws://h:-1/', 'ws://h:+80/', 'ws://h:$50/', 'ws://h:80a/',
    'ws://h:8 0/', 'ws://h:80:81/', 'ws://[::1]x/');
var
  I: Integer;
begin
  ExpectParsed('ws://h:1/', 'ws host=h port=1 resource=/ header=h:1');
  ExpectParsed('ws://h:65535/',
    'ws host=h port=65535 resource=/ header=h:65535');
  ExpectParsed('ws://h:0080/', 'ws host=h port=80 resource=/ header=h');
  for I := 0 to High(Rejected) do
    ExpectRejected(Rejected[I], BadPort);
end;

procedure TUrlForms.TestFragmentsRejected;
const
  Rejected: array[0..4] of string = (
    'ws://h/#x', 'ws://h#x', 'ws://h/p?q#f', 'wss://h:9/p#', 'ws://[::1]#');
var
  I: Integer;
begin
  for I := 0 to High(Rejected) do
    ExpectRejected(Rejected[I], Fragment);
end;

procedure TUrlForms.TestControlCharactersRejected;
const
  BadPaths: array[0..7] of string = (
    'ws://h/p'#13#10'X-Injected: 1', 'ws://h/p'#10, 'ws://h/p'#13,
    'ws://h/a b', 'ws://h/a'#9'b', 'ws://h/a'#0'b', 'ws://h/a'#127,
    'ws://h/?q='#13#10'X-Injected: 1');
  BadHosts: array[0..3] of string = (
    'ws://h'#13#10'X-Injected: 1/', 'ws://h'#10'x/', 'ws://h x/',
    'ws://h'#127'/');
var
  I: Integer;
begin
  // The error never echoes the URL, so the injected text cannot ride on
  // into a log line either.
  for I := 0 to High(BadPaths) do
    ExpectRejected(BadPaths[I], BadPath);
  for I := 0 to High(BadHosts) do
    ExpectRejected(BadHosts[I], BadHostChar);
  ExpectRejected('ws://[::1'#13#10']/', BadLiteral);
end;

procedure TUrlForms.TestBadHostsRejected;
const
  Missing: array[0..5] of string = (
    'ws://', 'ws:///p', 'ws://:80/', 'ws://user@/', 'ws://?x', 'ws://::1/');
  BadChars: array[0..4] of string = (
    'ws://a<b/', 'ws://a]b/', 'ws://a[b/', 'ws://a"b/', 'ws://a\b/');
  BadLiterals: array[0..4] of string = (
    'ws://[]/', 'ws://[v1.x]/', 'ws://[fe80::1%25eth0]/',
    'ws://[127.0.0.1]/', 'ws://[::g]/');
var
  I: Integer;
begin
  for I := 0 to High(Missing) do
    ExpectRejected(Missing[I], MissingHost);
  for I := 0 to High(BadChars) do
    ExpectRejected(BadChars[I], BadHostChar);
  for I := 0 to High(BadLiterals) do
    ExpectRejected(BadLiterals[I], BadLiteral);
  ExpectRejected('ws://[::1/', 'unterminated IPv6 literal in URL');
end;

procedure TUrlForms.TestBadSchemesRejected;
const
  Rejected: array[0..7] of string = (
    '', 'http://h/', 'https://h/', 'ws:/h', 'ws//h', 'wsx://h', 'h:80',
    ' ws://h/');
var
  I: Integer;
begin
  for I := 0 to High(Rejected) do
    ExpectRejected(Rejected[I], BadScheme);
end;

procedure TUrlForms.SetupTests;
begin
  Test('names and IPv4 addresses',                   TestNames);
  Test('scheme is case-insensitive',                 TestSchemeCase);
  Test('Host carries the port only when non-default', TestHostHeaderPort);
  Test('bracketed IPv6 literals',                    TestIPv6Literals);
  Test('userinfo is accepted and dropped',           TestUserinfoDropped);
  Test('resource name per RFC 6455 section 3',       TestResourceName);
  Test('port range 1..65535, digits only',           TestPortRange);
  Test('fragments are rejected',                     TestFragmentsRejected);
  Test('control characters and spaces are rejected', TestControlCharactersRejected);
  Test('bad hosts are rejected',                     TestBadHostsRejected);
  Test('foreign schemes are rejected',               TestBadSchemesRejected);
end;

begin
  TestRunnerProgram.AddSuite(TUrlForms.Create('Url: ws:// and wss:// parsing'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
