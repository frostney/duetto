# Architecture

## Executive Summary

- duetto implements RFC 6455 (WebSocket v13) and RFC 7692 (permessage-deflate) in ~2,700 lines of FreePascal.
- The heart is `WS.Protocol`, a **sans-I/O state machine** — one instance per connection, either role — that never touches a file descriptor.
- Every RFC rule lives in that one testable place; the blocking client, the epoll server, and the in-process benchmark all sit behind the same machine unchanged.
- Layers are strictly bottom-up: frame codec → UTF-8 → handshake → deflate → protocol machine → client / server.
- The server is a platform-neutral session layer over a completion-shaped **transport** seam (ADR-0001/0003): epoll on Linux, Network.framework on macOS (native `wss://`), IOCP on Windows. The client runs on POSIX and Windows (direct WinSock2) with TLS delegated to lwpt's `TransportSecurity`.

## The sans-I/O core

The owner of a `TWSProtocol` feeds raw socket bytes into `Ingest` and writes
whatever `OutPtr`/`OutPending` holds back to the socket; the machine never
performs I/O itself. Fragmentation, mask-direction policing, control-frame
interleave, fail-fast streaming UTF-8, close-code validation, RSV bits, and
deflate negotiation are all decided inside the machine.

`Ingest` mutates its buffer (in-place unmask) and returns `False` exactly
once on protocol failure, after queueing the appropriate close frame
(1002 / 1007 / 1009): the owner flushes the pending output, then drops TCP.

## Layers, bottom-up

| Unit | Role |
|------|------|
| `WS.Frame` | header parse/encode, strict minimal-length rules; masking via byte loop / UInt64 / SSE2 |
| `WS.Utf8` | Höhrmann DFA with an 8-byte-word ASCII fast path; resumable across fragments |
| `WS.Handshake` | upgrade request/response both directions, `Sec-WebSocket-Accept`, deflate parameter negotiation |
| `WS.Deflate` | RFC 7692 over paszlib: raw deflate, sync flush, 4-byte tail, context takeover control, inflate output cap |
| `WS.Protocol` | the sans-I/O machine above |
| `WS.Client` | blocking client, `ws://` and `wss://` (TLS via lwpt's TransportSecurity) |
| `WS.Transport` | the completion-shaped transport contract (ADR-0001): submit sends/closes, receive data/lifecycle completions on the transport's execution context (ADR-0003) |
| `WS.Transport.Epoll` | Linux transport: nonblocking sockets, one shared 256 KB read buffer, `EPOLLOUT` armed only while a connection has backlog |
| `WS.Transport.NetworkFramework` | macOS transport (ADR-0002): `nw_listener`/`nw_connection` C API, one serial dispatch queue per connection, native TLS via a PKCS#12 `SecIdentity` |
| `WS.Transport.Iocp` | Windows transport: one completion-port thread, `AcceptEx`/`WSARecv`/`WSASend` always armed overlapped, copy-on-send, outstanding-operation pinning for deferred frees |
| `WS.Server` | platform-neutral session layer: handshake accumulation, protocol wiring, flush/backpressure policy over the transport seam |

Units higher in the table never depend on units lower down. The programs in
`source/apps/` depend on the library, never the other way around.

## Validation strategy

Four nets, from innermost to outermost:

1. **Co-located unit suites** (`lwpt test`): RFC §5.7 frame vectors and
   strictness, an exhaustive 16.8M-case UTF-8 differential, handshake
   acceptance/rejection matrices, deflate round-trips with takeover and
   bomb-cap checks, and a 26-test protocol conformance suite asserting
   *wire* close codes for the violation matrix in both roles.
2. **`wsinterop`**: own client ↔ own server over real TCP, plus raw-socket
   violations (unmasked frame → 1002, invalid close code → 1002, fragmented
   ping → 1002, invalid UTF-8 → 1007).
3. **The Autobahn testsuite** in both directions via Docker — the industry
   conformance net. See [tooling.md](tooling.md#autobahn-testsuite) for how
   it runs and is judged.
4. **Cross-implementation checks**: `tools/crosscheck.py` validates against
   the Python `websockets` reference library in both directions, including
   fragmentation reassembly and permessage-deflate; the client also passes
   against a Rust `tungstenite` server.

## Performance

See [comparison.md](comparison.md) for measured benchmarks against
tungstenite (Rust) and `websockets` (Python), plus an architectural
comparison with tokio-websockets, fastwebsockets, websocket.zig, and
uWebSockets.
