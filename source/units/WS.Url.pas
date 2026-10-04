unit WS.Url;

// RFC 6455 §3 ws:// and wss:// URIs, parsed into what the client's
// opening handshake needs (§4.1): /host/, /port/, /resource name/, the
// /secure/ flag, and the Host header value. Pure string work, like
// WS.Handshake; TWSClient turns a refusal into EWSClient.
//
// Accepted: ws[s]://[userinfo@]host[:port][path][?query]
//
// - The scheme is case-insensitive (RFC 3986 §3.1).
// - host is a registered name or IPv4 address (RFC 3986 reg-name
//   characters, ASCII only: an internationalized name goes in as its
//   A-label; percent-escapes are passed through, never decoded) or a
//   bracketed IPv6 literal, '[::1]'. IPvFuture and RFC 6874 zone
//   identifiers are refused. A literal is checked for its characters
//   only; its shape is left to getaddrinfo, which the client calls
//   numeric-only for it, so '[1::2::3]' fails there ('cannot resolve')
//   and never reaches DNS.
// - userinfo ('user:pass@', RFC 3986 userinfo characters) is accepted
//   and dropped. The §3 ws-URI
//   grammar has no userinfo and RFC 6455 defines no use for credentials
//   in the URI, so they are never sent: not in the Host header, not in
//   the request line, not as an Authorization header.
// - port is 1..65535, digits only; absent or empty (RFC 3986 §3.2.3)
//   means the scheme default, 80 for ws and 443 for wss.
// - The resource name follows §3: '/' when the path is empty (so
//   'ws://h?x=1' requests '/?x=1'), then the path, then '?' and the
//   query when the query is non-empty.
// - A fragment ('#') is refused: §3 says fragment identifiers MUST NOT be
//   used on WebSocket URIs, and §4.1 step 1 fails the connection on a
//   URI that is not valid by §3. A literal '#' in a path is '%23'.
// - Control characters, space and DEL are refused anywhere in the host,
//   path or query, so a URL cannot inject header lines (CR/LF) or split
//   the request line. Other path and query bytes are sent as given.

{$I Shared.inc}

interface

type
  TWSUrl = record
    Secure: Boolean;      // wss
    Host: string;         // what resolution and TLS see: IPv6 without brackets
    IPv6Literal: Boolean; // Host came bracketed: numeric, never looked up
    Port: Integer;        // 1..65535, the scheme default when absent
    Resource: string;     // §3 resource name: path (at least '/') + '?query'
    HostHeader: string;   // §4.1 Host: brackets kept, port if non-default
    Authority: string;    // host:port for messages, brackets kept, port always
  end;

// False with AError set (and AUrl's text not echoed into it) when AUrl
// is not a ws:// or wss:// URI this client accepts.
function WSParseUrl(const AUrl: string; out AParsed: TWSUrl;
  out AError: string): Boolean;

implementation

uses
  SysUtils;

const
  WSDefaultPort = 80;
  WSDefaultSecurePort = 443;
  SchemeSeparator = '://';
  MaxPort = 65535;

  ErrScheme = 'URL must start with ws:// or wss://';
  ErrFragment = 'URL fragments are not allowed (RFC 6455 section 3)';
  ErrMissingHost = 'missing host in URL';
  ErrHostChar = 'invalid character in URL host';
  ErrUserinfoChar = 'invalid character in URL userinfo';
  ErrUnterminated = 'unterminated IPv6 literal in URL';
  ErrLiteral = 'bad IPv6 literal in URL';
  ErrPort = 'bad port in URL';
  ErrPath = 'control character or space in URL path or query';

// RFC 3986 reg-name: unreserved / pct-encoded / sub-delims.
function IsRegNameChar(C: Char): Boolean; inline;
begin
  case C of
    'A'..'Z', 'a'..'z', '0'..'9', '-', '.', '_', '~', '%',
    '!', '$', '&', '''', '(', ')', '*', '+', ',', ';', '=':
      Result := True;
  else
    Result := False;
  end;
end;

// What an IPv6address can be made of (RFC 3986 §3.2.2, an embedded IPv4
// tail included), with at least one colon. Shape is left to getaddrinfo
// (see the unit header).
function IsIPv6LiteralText(const S: string): Boolean;
var
  I: Integer;
begin
  for I := 1 to Length(S) do
    if not (S[I] in ['0'..'9', 'A'..'F', 'a'..'f', ':', '.']) then
      Exit(False);
  Result := Pos(':', S) > 0;
end;

// AColonToo admits ':' as well: RFC 3986 userinfo is reg-name plus ':'.
function IsRegName(const S: string; AColonToo: Boolean = False): Boolean;
var
  I: Integer;
begin
  for I := 1 to Length(S) do
    if not (IsRegNameChar(S[I]) or (AColonToo and (S[I] = ':'))) then
      Exit(False);
  Result := True;
end;

// Control characters, space and DEL: none may reach the request line or
// a header (CR/LF would start a new header line).
function HasControlOrSpace(const S: string): Boolean;
var
  I: Integer;
begin
  for I := 1 to Length(S) do
    if (S[I] <= ' ') or (S[I] = #127) then Exit(True);
  Result := False;
end;

// An empty port is the scheme default (RFC 3986 §3.2.3): APort is left
// alone and the result is True.
function ParsePort(const AText: string; var APort: Integer): Boolean;
var
  I, Value: Integer;
begin
  if AText = '' then Exit(True);
  Result := False;
  Value := 0;
  for I := 1 to Length(AText) do
  begin
    if not (AText[I] in ['0'..'9']) then Exit;
    Value := Value * 10 + (Ord(AText[I]) - Ord('0'));
    if Value > MaxPort then Exit;
  end;
  if Value = 0 then Exit;
  APort := Value;
  Result := True;
end;

function ParseScheme(const AUrl: string; out ASecure: Boolean;
  out ARest: string): Boolean;
var
  Sep: Integer;
  Scheme: string;
begin
  Sep := Pos(SchemeSeparator, AUrl);
  Scheme := LowerCase(Copy(AUrl, 1, Sep - 1));
  ASecure := Scheme = 'wss';
  ARest := Copy(AUrl, Sep + Length(SchemeSeparator), MaxInt);
  Result := (Sep > 0) and (ASecure or (Scheme = 'ws'));
end;

function SchemeDefaultPort(ASecure: Boolean): Integer;
begin
  if ASecure then
    Result := WSDefaultSecurePort
  else
    Result := WSDefaultPort;
end;

// AHostPort is the authority with any userinfo already dropped. '' when
// it parses, else the error.
function ParseHostPort(const AHostPort: string; var AParsed: TWSUrl): string;
var
  Bracket: Integer;
  PortText: string;
begin
  if (AHostPort <> '') and (AHostPort[1] = '[') then
  begin
    Bracket := Pos(']', AHostPort);
    if Bracket = 0 then Exit(ErrUnterminated);
    AParsed.Host := Copy(AHostPort, 2, Bracket - 2);
    AParsed.IPv6Literal := True;
    if not IsIPv6LiteralText(AParsed.Host) then Exit(ErrLiteral);
    // Nothing but ':port' (or nothing) may follow the bracket.
    PortText := Copy(AHostPort, Bracket + 1, MaxInt);
    if (PortText <> '') and (PortText[1] <> ':') then Exit(ErrPort);
    Delete(PortText, 1, 1);
  end
  else
  begin
    AParsed.Host := AHostPort;
    PortText := '';
    Bracket := Pos(':', AHostPort);
    if Bracket > 0 then
    begin
      AParsed.Host := Copy(AHostPort, 1, Bracket - 1);
      PortText := Copy(AHostPort, Bracket + 1, MaxInt);
    end;
    if AParsed.Host = '' then Exit(ErrMissingHost);
    if not IsRegName(AParsed.Host) then Exit(ErrHostChar);
  end;
  if not ParsePort(PortText, AParsed.Port) then Exit(ErrPort);
  Result := '';
end;

// §3 resource name from everything after the authority: '' or a string
// starting with '/' or '?'.
function BuildResource(const ATail: string): string;
var
  Query: Integer;
begin
  Result := ATail;
  if (Result = '') or (Result[1] = '?') then Result := '/' + Result;
  // '?' only when the query component is non-empty.
  Query := Pos('?', Result);
  if Query = Length(Result) then SetLength(Result, Query - 1);
end;

function WSParseUrl(const AUrl: string; out AParsed: TWSUrl;
  out AError: string): Boolean;
var
  Rest, Authority, Host: string;
  Stop, I: Integer;
begin
  Result := False;
  AParsed := Default(TWSUrl);
  AError := '';
  if not ParseScheme(AUrl, AParsed.Secure, Rest) then
  begin
    AError := ErrScheme;
    Exit;
  end;
  AParsed.Port := SchemeDefaultPort(AParsed.Secure);
  if Pos('#', Rest) > 0 then
  begin
    AError := ErrFragment;
    Exit;
  end;

  // The authority runs to the first '/' or '?'.
  Stop := Length(Rest) + 1;
  for I := 1 to Length(Rest) do
    if (Rest[I] = '/') or (Rest[I] = '?') then
    begin
      Stop := I;
      Break;
    end;
  Authority := Copy(Rest, 1, Stop - 1);
  AParsed.Resource := BuildResource(Copy(Rest, Stop, MaxInt));

  // Userinfo ends at the last '@' of the authority and is dropped, but
  // only valid userinfo is: with a '\' or a space in it, a browser-style
  // parser would see a different host than this one.
  I := LastDelimiter('@', Authority);
  if not IsRegName(Copy(Authority, 1, I - 1), True) then
  begin
    AError := ErrUserinfoChar;
    Exit;
  end;
  Delete(Authority, 1, I);
  AError := ParseHostPort(Authority, AParsed);
  if AError <> '' then Exit;
  if HasControlOrSpace(AParsed.Resource) then
  begin
    AError := ErrPath;
    Exit;
  end;

  if AParsed.IPv6Literal then
    Host := '[' + AParsed.Host + ']'
  else
    Host := AParsed.Host;
  AParsed.Authority := Host + ':' + IntToStr(AParsed.Port);
  // §4.1: the port only when it is not this scheme's default.
  if AParsed.Port = SchemeDefaultPort(AParsed.Secure) then
    AParsed.HostHeader := Host
  else
    AParsed.HostHeader := AParsed.Authority;
  Result := True;
end;

end.
