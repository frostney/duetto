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
//   characters; percent-encoding is passed through, never decoded) or a
//   bracketed IPv6 literal, '[::1]'. IPvFuture and RFC 6874 zone
//   identifiers are refused.
// - userinfo ('user:pass@') is accepted and dropped. The §3 ws-URI
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
//   the request line.

{$I Shared.inc}

interface

const
  WSDefaultPort = 80;
  WSDefaultSecurePort = 443;

type
  TWSUrl = record
    Secure: Boolean;      // wss
    Host: string;         // what resolution and TLS see: IPv6 without brackets
    IPv6Literal: Boolean; // Host came bracketed: numeric, never looked up
    Port: Integer;        // 1..65535, the scheme default when absent
    Resource: string;     // §3 resource name: path (at least '/') + '?query'
    HostHeader: string;   // §4.1 Host: brackets kept, port if non-default
  end;

// False with AError set (and AUrl's text not echoed into it) when AUrl
// is not a ws:// or wss:// URI this client accepts.
function WSParseUrl(const AUrl: string; out AParsed: TWSUrl;
  out AError: string): Boolean;

implementation

uses
  SysUtils;

const
  SchemeSeparator = '://';
  MaxPort = 65535;

// RFC 3986 reg-name: unreserved / pct-encoded / sub-delims. Bytes above
// ASCII pass, so an internationalized name reaches the resolver as given.
function IsRegNameChar(C: Char): Boolean; inline;
begin
  case C of
    'A'..'Z', 'a'..'z', '0'..'9', '-', '.', '_', '~', '%',
    '!', '$', '&', '''', '(', ')', '*', '+', ',', ';', '=', #128..#255:
      Result := True;
  else
    Result := False;
  end;
end;

// What an IPv6address can be made of (RFC 3986 §3.2.2, an embedded IPv4
// tail included). Shape is left to getaddrinfo, which the client calls
// numeric-only for a literal, so a malformed one never reaches DNS.
function IsIPv6LiteralChar(C: Char): Boolean; inline;
begin
  case C of
    '0'..'9', 'A'..'F', 'a'..'f', ':', '.':
      Result := True;
  else
    Result := False;
  end;
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

function ParsePort(const AText: string; out APort: Integer): Boolean;
var
  I: Integer;
begin
  Result := False;
  APort := 0;
  if AText = '' then Exit;
  for I := 1 to Length(AText) do
  begin
    if not (AText[I] in ['0'..'9']) then Exit;
    APort := APort * 10 + (Ord(AText[I]) - Ord('0'));
    if APort > MaxPort then Exit;
  end;
  Result := APort > 0;
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

// AHostPort is the authority with any userinfo already dropped.
function ParseHostPort(const AHostPort: string; var AParsed: TWSUrl;
  out AError: string): Boolean;
var
  Bracket, Colon, I: Integer;
  PortText: string;
  HasPort: Boolean;
begin
  Result := False;
  HasPort := False;
  PortText := '';
  if (AHostPort <> '') and (AHostPort[1] = '[') then
  begin
    Bracket := Pos(']', AHostPort);
    if Bracket = 0 then
    begin
      AError := 'unterminated IPv6 literal in URL';
      Exit;
    end;
    AParsed.Host := Copy(AHostPort, 2, Bracket - 2);
    AParsed.IPv6Literal := True;
    if Pos(':', AParsed.Host) = 0 then
    begin
      AError := 'bad IPv6 literal in URL';
      Exit;
    end;
    for I := 1 to Length(AParsed.Host) do
      if not IsIPv6LiteralChar(AParsed.Host[I]) then
      begin
        AError := 'bad IPv6 literal in URL';
        Exit;
      end;
    if Bracket < Length(AHostPort) then
    begin
      if AHostPort[Bracket + 1] <> ':' then
      begin
        AError := 'bad port in URL';
        Exit;
      end;
      HasPort := True;
      PortText := Copy(AHostPort, Bracket + 2, MaxInt);
    end;
  end
  else
  begin
    Colon := Pos(':', AHostPort);
    if Colon > 0 then
    begin
      HasPort := True;
      PortText := Copy(AHostPort, Colon + 1, MaxInt);
      AParsed.Host := Copy(AHostPort, 1, Colon - 1);
    end
    else
      AParsed.Host := AHostPort;
    if AParsed.Host = '' then
    begin
      AError := 'missing host in URL';
      Exit;
    end;
    for I := 1 to Length(AParsed.Host) do
      if not IsRegNameChar(AParsed.Host[I]) then
      begin
        AError := 'invalid character in URL host';
        Exit;
      end;
  end;

  // An empty port after the colon is the default (RFC 3986 §3.2.3).
  if HasPort and (PortText <> '') and not ParsePort(PortText, AParsed.Port) then
  begin
    AError := 'bad port in URL';
    Exit;
  end;
  Result := True;
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

function BuildHostHeader(const AParsed: TWSUrl): string;
var
  DefaultPort: Integer;
begin
  if AParsed.IPv6Literal then
    Result := '[' + AParsed.Host + ']'
  else
    Result := AParsed.Host;
  if AParsed.Secure then
    DefaultPort := WSDefaultSecurePort
  else
    DefaultPort := WSDefaultPort;
  if AParsed.Port <> DefaultPort then
    Result := Result + ':' + IntToStr(AParsed.Port);
end;

function WSParseUrl(const AUrl: string; out AParsed: TWSUrl;
  out AError: string): Boolean;
var
  Rest, Authority: string;
  Stop, I: Integer;
begin
  Result := False;
  AParsed := Default(TWSUrl);
  AError := '';
  if not ParseScheme(AUrl, AParsed.Secure, Rest) then
  begin
    AError := 'URL must start with ws:// or wss://';
    Exit;
  end;
  if AParsed.Secure then
    AParsed.Port := WSDefaultSecurePort
  else
    AParsed.Port := WSDefaultPort;
  if Pos('#', Rest) > 0 then
  begin
    AError := 'URL fragments are not allowed (RFC 6455 section 3)';
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

  // Userinfo ends at the last '@' of the authority; it is dropped.
  Delete(Authority, 1, LastDelimiter('@', Authority));
  if not ParseHostPort(Authority, AParsed, AError) then Exit;
  if HasControlOrSpace(AParsed.Resource) then
  begin
    AError := 'control character or space in URL path or query';
    Exit;
  end;
  AParsed.HostHeader := BuildHostHeader(AParsed);
  Result := True;
end;

end.
