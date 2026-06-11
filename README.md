# lwws — lightweight WebSocket for Pascal

RFC 6455 (v13) + RFC 7692 permessage-deflate in FreePascal, built and tested
with [lwpt](https://github.com/frostney/lwpt). ~2,700 lines for the whole
library: frame codec, incremental UTF-8, opening handshake, deflate,
a sans-I/O connection state machine, a blocking client, and a
single-threaded epoll server.

## Design

The heart is `WS.Protocol` — a **sans-I/O state machine** (one per
connection, either role). The owner feeds raw socket bytes into `Ingest`
and writes whatever `OutPtr`/`OutPending` holds back to the socket; the
machine never touches a file descriptor. Every RFC 6455 rule —
fragmentation, mask-direction policing, control-frame interleave,
fail-fast streaming UTF-8, close-code validation, RSV bits, deflate —
lives in that one testable place, so the same machine sits behind the
blocking client, the epoll server, and the in-process benchmark unchanged.

`Ingest` mutates its buffer (in-place unmask) and returns `False` exactly
once on protocol failure, after queueing the appropriate close frame
(1002 / 1007 / 1009): flush, then drop TCP.

Layers, bottom-up:

| Unit | Role |
|------|------|
| `WS.Frame` | header parse/encode, strict minimal-length rules; masking via byte loop / UInt64 / SSE2 |
| `WS.Utf8` | Höhrmann DFA with an 8-byte-word ASCII fast path; resumable across fragments |
| `WS.Handshake` | upgrade request/response both directions, `Sec-WebSocket-Accept`, deflate parameter negotiation |
| `WS.Deflate` | RFC 7692 over paszlib: raw deflate, sync flush, 4-byte tail, context takeover control, inflate output cap |
| `WS.Protocol` | the sans-I/O machine above |
| `WS.Client` | blocking client, `ws://` and `wss://` (TLS via lwpt's TransportSecurity) |
| `WS.Server` | Linux epoll reactor: nonblocking sockets, one shared 256 KB read buffer, `EPOLLOUT` armed only while a connection has backlog |

## Programs

```
lwpt install              # resolve deps (expects lwpt as a sibling checkout; see lwpt.toml)
lwpt test                 # five suites, all green
lwpt build --mode release
build/wsecho [--port=N] [--no-deflate] [--quiet]   # echo server
build/wsprobe ws://host:port/ [--deflate]          # client probe vs any server
build/wsinterop                                    # live-socket battery, exit 0 = pass
build/wsbench                                      # component benchmarks
```

## Validation

`lwpt test` runs five suites: RFC §5.7 frame vectors and strictness, an
exhaustive 16.8M-case UTF-8 differential, handshake acceptance/rejection
matrices, deflate round-trips with takeover and bomb-cap checks, and a
26-test protocol conformance suite asserting *wire* close codes for the
violation matrix in both roles.

On top of that: `wsinterop` (own client ↔ own server over TCP, plus
raw-socket violations: unmasked frame → 1002, invalid close code → 1002,
fragmented ping → 1002, invalid UTF-8 → 1007) and
`tools/crosscheck.py`, which validates against the Python `websockets`
reference library in **both directions** — including fragmentation
reassembly and permessage-deflate — plus four more crafted violations.
The client also passes against a Rust `tungstenite` server.

The Autobahn fuzzing suite was not run (Python 2 only); the conformance
suite and raw-socket batteries mirror its core cases.

## Numbers

See [COMPARISON.md](COMPARISON.md) for measured benchmarks against
tungstenite (Rust) and `websockets` (Python), plus an architectural
comparison with tokio-websockets, fastwebsockets, websocket.zig, and
uWebSockets. Headline, on one shared 2.8 GHz core: 2.35 M full protocol
round-trips/s at 64 B in-process (2.72 GB/s full-duplex at 256 KiB via
streaming ingest); 3.1 µs opening handshakes; 154 k echo msg/s under
uWebSockets `load_test` — 1.4× the tungstenite baseline on the same box.
