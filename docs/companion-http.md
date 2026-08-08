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
  block the mixed combination.
- Secure-context gotcha: powerful APIs (WebCodecs and friends) silently
  disappear on plain `http://` over a LAN IP; `localhost` is a secure
  context, LAN IPs are not.
- Reference implementation:
  [lantaarn](https://github.com/frostney/lantaarn).

## The two-port layout

The host runs two listeners in one process: `fphttpserver` hands out the
page, duetto handles the WebSocket. `fphttpserver`'s accept loop blocks,
so it lives on a `TThread` (which needs `cthreads` on Unix — duetto's
server requires it anyway):

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
match — both plain, or both TLS. For the TLS pair, `TWSServer` takes a
`TWSTransportTls` record (PKCS#12 identity; native on macOS via
Network.framework — see the `--pkcs12` flags on `wsecho`), and the
companion server must serve `https://` too. The other direction
(`http://` page opening `wss://`) is allowed.

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

## Toward a single port

An opt-in raw-HTTP fallback hook on the handshake path —
`TWSServer.OnPlainRequest` — is being added so a host can answer plain
GETs from the WebSocket port itself and skip the second listener for
the single-page case. Until it ships, the two-port layout above is the
supported pattern; it also remains the right choice whenever the HTTP
side outgrows one page.
