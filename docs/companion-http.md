# Companion HTTP

## Executive Summary

- duetto is deliberately **not an HTTP framework** ([VISION.md](../VISION.md)) —
  it speaks exactly enough HTTP/1.1 for the RFC 6455 handshake. A browser
  needs a page before it can open the WebSocket, so browser-facing hosts
  serve that page themselves.
- The pattern: a small companion HTTP server (e.g. `fphttpserver` on its
  own thread) on one port, `TWSServer` on another.
- Substitute the live WebSocket port into the served page at startup so
  the browser knows where duetto is listening.
- Pair `ws://` with `http://` and `wss://` with `https://` — browsers
  block the mixed combination. Server-side TLS terminates **natively on
  all three platforms** (macOS via Network.framework, Linux via lwpt's
  OpenSSL memory-BIO accept, Windows — x64 and win32 — via lwpt's
  SChannel accept), with the caveat that the Linux transport needs
  libssl/libcrypto 3 loadable at runtime; a TLS-terminating reverse
  proxy in front of a plain listener stays a valid alternative where
  those libraries are absent.
- Secure-context gotcha: powerful APIs (WebCodecs and friends) silently
  disappear on plain `http://` over a LAN IP; `localhost` is a secure
  context, LAN IPs are not.
- Reference implementation:
  [lantaarn](https://github.com/frostney/lantaarn).
- Single-page hosts can skip the second listener entirely:
  `TWSServer.OnPlainRequest` answers body-less GET/HEAD from the
  WebSocket port itself (one response, then close).

## The two-port layout

The host runs two listeners in one process: `fphttpserver` hands out the
page, duetto handles the WebSocket. `fphttpserver`'s accept loop blocks,
so it lives on a `TThread` — and that is what pulls in `cthreads` here:
any FPC program creating a `TThread` on Unix needs it for the RTL's
threading. duetto does not require it across the board on Linux; a
single-threaded epoll server never touches another thread. It becomes
necessary when you call `Conn.Post` from another thread, and on macOS,
where the Network.framework transport delivers callbacks on GCD
threads:

```pascal
uses
  {$ifdef UNIX} cthreads, {$endif}
  Classes, SysUtils, fphttpserver, httpdefs,
  WS.Server;

type
  TPageServer = class(TThread)
  private
    FServer: TFPHTTPServer;
    FPort: Word;
    FPage: RawByteString;
    procedure HandleRequest(ASender: TObject;
      var ARequest: TFPHTTPConnectionRequest;
      var AResponse: TFPHTTPConnectionResponse);
  protected
    procedure Execute; override;
  public
    constructor Create(APort: Word; const APage: RawByteString);
  end;

constructor TPageServer.Create(APort: Word; const APage: RawByteString);
begin
  FPort := APort;
  FPage := APage;
  FreeOnTerminate := False;
  inherited Create(False);   // start immediately
end;

procedure TPageServer.HandleRequest(ASender: TObject;
  var ARequest: TFPHTTPConnectionRequest;
  var AResponse: TFPHTTPConnectionResponse);
begin
  AResponse.Code := 200;
  AResponse.ContentType := 'text/html; charset=utf-8';
  AResponse.Content := FPage;
  AResponse.SendContent;
end;

procedure TPageServer.Execute;
begin
  FServer := TFPHTTPServer.Create(nil);
  try
    FServer.Threaded := True;
    FServer.Port := FPort;
    FServer.OnRequest := HandleRequest;
    FServer.Active := True;   // blocks until Active := False
  finally
    FreeAndNil(FServer);
  end;
end;
```

Wiring it up — duetto first, so the real port (relevant with an
ephemeral `--port=0`) can be substituted into the page:

```pascal
Ws := TWSServer.Create(5801);
Ws.OnMessage := App.HandleMessage;   // TWSServerMessage handler
Page := TPageServer.Create(5800,
  StringReplace(ViewerHtml, '%WS_PORT%', IntToStr(Ws.Port),
    [rfReplaceAll]));
Ws.Run;   // blocks until Ws.Stop
```

Handlers run on the transport's execution context — see the concurrency
notes at the top of `source/units/WS.Server.pas` and
[architecture.md](architecture.md) before sharing state between the two
servers.

## Injecting the live WebSocket port

The page is a template with a `%WS_PORT%` token, replaced once at
startup (the `StringReplace` above). The page then connects back to the
host it was served from:

```js
const ws = new WebSocket(`ws://${location.hostname}:%WS_PORT%/`);
```

Using `location.hostname` rather than a hard-coded host means the same
binary works via `localhost`, a LAN IP, or a DNS name without
configuration — only the port needs injecting.

## ws:// pairs with http://, wss:// with https://

Browsers apply mixed-content rules to WebSockets: a page served over
`https://` **cannot** open a `ws://` connection. The two listeners must
match — both plain, or both TLS. The other direction (`http://` page
opening `wss://`) is allowed.

How you get the TLS pair depends on the platform:

`TWSServer` takes a `TWSTransportTls` record (a PKCS#12 identity plus
optional flow-control tuning) on every platform, and the transport
terminates TLS itself — see the `--pkcs12` flags on `wsecho`. Whichever
platform you are on, the companion server must serve `https://` too.

- **macOS.** Network.framework terminates TLS inside the platform stack
  (ADR-0002); only the identity fields of the record are read.
- **Linux and Windows.** The epoll and IOCP transports terminate TLS
  over lwpt's memory-BIO accept API
  ([duetto#22](https://github.com/frostney/duetto/issues/22)) — OpenSSL
  on Linux, native SChannel on Windows (x64 and win32, no DLLs to ship).
  On Linux OpenSSL 3 has to be loadable at runtime (`libssl.so.3` /
  `libcrypto.so.3` from the usual library paths); without it the server
  context fails to build, and a
  TLS-terminating reverse proxy (nginx, Caddy, HAProxy) in front of a
  plain `http://` + `ws://` pair on loopback remains a valid shape.

## Secure contexts: the disappearing-API trap

Some browser APIs — WebCodecs, and most other "powerful features" —
exist only in a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts).
`http://localhost` counts as secure; `http://192.168.x.y` does **not**.
The failure mode is quiet: the constructor is simply `undefined`, so
feature detection that passed all through local development fails the
first time the page is opened from another machine — easily an hour of
debugging the wrong layer. Either keep a non-secure-context fallback in
the page (lantaarn's viewer falls back from WebCodecs to an MSE muxer
for exactly this reason) or serve the `https://` + `wss://` pair.

## Reference implementation

[lantaarn](https://github.com/frostney/lantaarn) — a browser-reachable
remote desktop on duetto — is the worked example of this recipe: its
`Lantaarn.Http` unit is the companion server above (single embedded
page, `%WS_PORT%` substitution), and its `docs/architecture.md` shows
the two-port process shape end to end.

## Single port: OnPlainRequest

For the single-page case the second listener is optional:
`TWSServer.OnPlainRequest` is an opt-in hook on the handshake path
that hands well-formed non-upgrade requests to the host instead of
refusing them. One origin, one port — and because the listener can carry
a TLS identity on every platform, the `https://` page and the `wss://`
socket share it, which settles the pairing and secure-context sections
above by construction. The same single-port shape works over plain
`http://` + `ws://` when TLS is terminated by a reverse proxy in front
of it instead:

```pascal
function THost.PlainRequest(const AHS: TWSServerHandshake;
  const ARawRequest: RawByteString;
  out AResponse: RawByteString): Boolean;
var
  IsHead: Boolean;
begin
  IsHead := SameText(AHS.Method, 'HEAD');
  Result := (IsHead or SameText(AHS.Method, 'GET')) and (AHS.Path = '/');
  if Result then
  begin
    AResponse :=
      'HTTP/1.1 200 OK'#13#10 +
      'Content-Type: text/html; charset=utf-8'#13#10 +
      'Content-Length: ' + IntToStr(Length(FPage)) + #13#10 +
      'Connection: close'#13#10#13#10;
    // AResponse is written verbatim, so a HEAD reply must carry the
    // headers a GET would — including Content-Length — but no body.
    if not IsHead then
      AResponse := AResponse + FPage;
  end;
end;

Ws.OnPlainRequest := Host.PlainRequest;
```

The contract is deliberately narrow:

- **Scope: body-less requests only.** The hook fires for a well-formed
  GET or HEAD with no `Content-Length` and no `Transfer-Encoding` that
  is not a WebSocket upgrade attempt. Everything else — requests
  advertising a body, malformed noise, broken upgrade attempts — keeps
  the standard refusal, as does every request while the property is
  unset.
- **Single-shot.** Return `True` with a complete HTTP/1.1 response in
  `AResponse` (status line, headers, body; include `Connection: close`
  so clients expect what follows): the bytes are written verbatim and
  the connection closes. No keep-alive loop, no routing, no file
  serving — the host writes raw bytes. Return `False` for the standard
  refusal.
- **Request access.** `AHS` carries `Method`, `Path` and `Host` as
  parsed by `WS.Handshake`; `WS.Handshake.HeaderValue` reads any other
  header out of `ARawRequest`. Note the type step: `HeaderValue` is
  declared `(const ARaw, AName: string): string`, so passing
  `ARawRequest` (a `RawByteString`) goes through an implicit conversion
  in Delphi mode. Header names and values are ASCII by RFC 9110, so
  this is safe for lookup — just don't route non-ASCII request bytes
  back out through it.
- **Threading.** The hook fires on the connection's execution context
  like every other callback (ADR-0003).

The two-port layout above remains the right choice the moment the HTTP
side outgrows one page — multiple assets, caching, redirects, anything
that starts to resemble routing belongs in a real HTTP server, not in
this hook.
