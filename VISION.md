# Vision

## Mission

duetto is a WebSocket implementation for Object Pascal whose throughput
and latency rival C and Rust implementations — on a fully conformant
protocol core. Fast numbers only count on a correct implementation:
strict RFC 6455/7692 behaviour (right close code for every violation,
both directions of the Autobahn suite) is the baseline the performance
claim stands on, never a trade-off against it.

Cross-platform coverage (Linux, macOS, Windows) and embeddability
(a library that compiles into the host binary via lwpt, with no runtime
dependencies beyond its declared TLS delegation) are givens of being a
serious library, not goals — a WebSocket library that serves one
platform or can't be embedded is half a library.

## Product direction

One sans-I/O protocol core (`WS.Protocol` and the units under it) owns
every protocol rule and performs no I/O. Everything else is delivery:
a blocking client, and a server whose per-platform backends — epoll
(Linux), Network.framework (macOS), IOCP (Windows) — implement one
completion-shaped seam ([ADR-0001](docs/adr/0001-completion-shaped-backend-seam.md),
[ADR-0002](docs/adr/0002-network-framework-backend-macos.md)). The same
tested core sits behind every entry point unchanged.

duetto is a member of the lwpt ecosystem: built, tested, formatted, and
released through lwpt; TLS delegated to lwpt's TransportSecurity (and
platform-native stacks where the backend brings its own); consumable by
any lwpt project — including, prospectively, as the networking
substrate for hosts like GocciaScript runtime extensions.

## Principles

- **Performance counts only on conformance.** A benchmark win from a
  non-strict shortcut is a loss.
- **One protocol core.** Protocol behaviour never leaks into the
  client, the server, backends, or apps.
- **Hot paths avoid the RTL** when a `wsbench` measurement justifies it
  (see [code-style.md](docs/code-style.md)); crypto is never
  hand-rolled — that is what TLS delegation is for.
- **Honest measurement.** Comparisons run under identical conditions in
  one environment, published with their caveats
  ([comparison.md](docs/comparison.md)); benchmark numbers never become
  CI assertions.
- **Current truth beats aspirational documentation.** Docs describe
  shipped behaviour; planned behaviour lives in investigated issues.
- **Exemplary lwpt citizenship.** Manifest-driven, lockfile-verified,
  committed dependency state, one toolchain entry point.

## What duetto is not

- **Not an HTTP framework** — duetto speaks exactly enough HTTP/1.1 to
  perform the RFC 6455 handshake; routing, middleware, and file serving
  are out.
- **Not a messaging framework** — no rooms, pub/sub, presence, or
  automatic reconnect policy. duetto is the protocol layer; application
  semantics belong to the host. (Ping/pong stays — that is RFC 6455.)
- **Not a TLS implementation** — TLS is delegated: lwpt
  TransportSecurity on the client, lwpt's accept-side backend and
  platform-native stacks on the server. duetto never hand-rolls crypto.
- **Not a general-purpose async framework** — the completion seam is an
  internal architecture boundary, not a public event-loop API for
  non-WebSocket use.
- **Not a legacy-protocol shim** — RFC 6455 (v13) only; no hixie/hybi
  draft support, ever.
- **WebSocket over HTTP/2 and HTTP/3 (RFC 8441/9220) is not a current
  goal** — deferred, not rejected; the scoping analysis is tracked in
  [#6](https://github.com/frostney/duetto/issues/6).

## Related documents

- [Architecture](docs/architecture.md) — the sans-I/O split and layering
- [Comparison](docs/comparison.md) — measured performance posture
- [Code style](docs/code-style.md) — including the hot-path RTL policy
- [CONTEXT.md](CONTEXT.md) — canonical glossary
- [docs/adr/](docs/adr/) — architectural decisions
