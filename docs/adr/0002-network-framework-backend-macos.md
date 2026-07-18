# ADR 0002 — Network.framework backend on macOS; kqueue dropped

Date: 2026-07-19
Status: accepted

## Context

The obvious macOS port of the epoll reactor is kqueue over raw fds.
But server-side TLS then needs a TLS layer that works over caller-owned
fds on macOS: SecureTransport is deprecated (and its server mode is
capped at TLS 1.2), and Network.framework cannot adopt or expose a fd —
it owns the socket lifecycle entirely. The fd path would therefore pull
in an OpenSSL dependency on macOS.

Network.framework has a complete C API (`nw_listener`,
`nw_connection`, macOS 10.14+) that is linkable from FPC without
Swift, is completion-based — the exact shape of the ADR-0001 seam —
and provides native TLS 1.3 server support via `sec_protocol_options`.

Ecosystem precedent splits the same way: Apple's own server-side Swift
stack (SwiftNIO) vendors BoringSSL for fd-owning servers, while
swift-nio-transport-services re-hosts NIO on Network.framework taken
whole. Nobody layers OS TLS over their own fds on macOS.

## Decision

The macOS server backend is Network.framework via its C API,
implementing the ADR-0001 completion seam. It owns sockets, the event
loop, and TLS on that platform. kqueue is not built: with
Network.framework serving macOS, no in-scope platform needs it. It
returns only if BSD support ever becomes a goal.

## Consequences

- macOS gets the full program set (`wsecho`, `wsinterop`) and native
  `wss://` with zero new dependencies.
- Server-side TLS work in lwpt's TransportSecurity shrinks to the
  fd-owning backends (Linux epoll now, Windows IOCP later).
- macOS server throughput flows through Apple's stack, so macOS numbers
  are not comparable to the Linux benchmarks and stay out of
  [comparison.md](../comparison.md)'s measured tables.
- The seam gains a second, natively completion-based implementation
  before IOCP starts — early proof it is not secretly epoll-shaped.
