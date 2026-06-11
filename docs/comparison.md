# duetto vs Rust, Zig, Python, C++ — measured where possible, honest where not

Everything in the **measured** sections ran in this environment on
2026-06-11. Everything in the **analytical** section is from
documentation and published benchmarks, clearly labelled.

## Environment (read this first)

One vCPU: Intel Xeon @ 2.80 GHz, kernel 6.18.5, loopback only. The load
generator and the server **share that single core**, so absolute numbers
are conservative and the handicap is identical for every contender —
treat the comparisons as relative. FPC 3.2.2 `-O2`; rustc 1.75 (apt) with
tungstenite 0.21.0 (`idna_adapter` pinned to 1.1.0 — current releases
need edition2024); CPython 3.12.3 with `websockets` 16.0; uWebSockets
`load_test` built from source (gcc `-O3`, no-SSL, epoll).

## Component benchmarks (duetto internals, `wsbench`)

| Subject | Result |
|---|---|
| Masking — naive byte loop | 1.50 GB/s |
| Masking — UInt64 XOR | 20.4 GB/s |
| Masking — SSE2 | 24.4 GB/s |
| Frame header parse (mixed 7/16-bit lengths) | 31.0 M frames/s |
| UTF-8 — ASCII fast path | 3.00 GB/s |
| UTF-8 — pure Höhrmann DFA | 0.49 GB/s |
| UTF-8 — mixed CJK/ASCII | 0.32 GB/s |
| Opening handshake (parse + respond) | 325 k/s (3.1 µs each) |
| Deflate compress (JSON-ish, ratio 6.2%) | 92 MB/s |
| Inflate | 425 MB/s |

Full in-process round-trip — two `TWSProtocol` machines piped
back-to-back, so every message is masked, parsed, validated and unmasked
twice, no sockets:

| Payload | Round-trips/s | Full-duplex |
|---|---|---|
| 64 B | 2,348,813 | 287 MB/s |
| 1 KiB | 1,760,684 | 3.4 GB/s |
| 16 KiB | 221,100 | 6.9 GB/s |
| 256 KiB | 5,442 | 2.72 GB/s |

That is ~210 ns per message through the complete protocol surface at
64 B. Two hot spots from the first round of measurement were fixed and
re-measured:

**Handshake, 87 µs → 3.1 µs (28×).** Two causes. First, an FPC codegen
gotcha worth knowing: `LocalStr := FuncReturningString(...)` routes the
hidden result through a nil temporary, so a function built from repeated
`Result := Result + ...` reallocates per append *and per call* — the
identical statement assigned to a **global** reuses the destination
buffer in place and ran 9× faster (8.8 µs vs 82 µs, stable across runs).
The response/request builders now write into a stack buffer and
materialise the string once, making cost independent of the caller's
destination; base64 was also inlined (the FCL routes it through two
stream objects per call). Second, the parser rescanned the whole request
once per header it wanted; a single-pass collector fixed that. The
remaining 3.1 µs is mostly SHA-1.

**256 KiB round-trips, 2,329 → 5,442/s (2.3×).** Ingest previously
buffered whole frames, so any frame larger than one Ingest call
round-tripped through the carry buffer as a full extra copy plus a
header reparse. Data payloads now stream: header parsed once, then each
chunk is unmasked in place (mask phase carried across calls) and routed
straight into message assembly or the inflater. The carry buffer now
only ever holds a partial header or a split control frame (≤ ~139 B).
Cost of the extra streaming branch: ~5% at 64 B (2.46 M → 2.35 M), which
is the trade for bounded memory and the 2.3× at large sizes.

## End-to-end echo (uWebSockets `load_test`, 100 connections)

The same methodology tokio-websockets uses for its published numbers:
`load_test` opens N connections, each ping-pongs one message. Best
steady-state 4-second window of two, plain echo, deflate off:

| Payload | duetto (epoll) | tungstenite 0.21 (thread/conn) | `websockets` 16.0 (asyncio) |
|---|---|---|---|
| 20 B | **154,252 msg/s** | 110,440 | 21,637 |
| 1 KiB | **142,457 msg/s** | 105,360 | 19,186 |
| 16 KiB | **78,863 msg/s** | 60,077 | 23,942 |
| 256 KiB | **4,673 msg/s** | 4,074 | — |

duetto holds ~1.4× tungstenite at 20 B and 1 KiB, ~1.3× at 16 KiB, and
~1.15× at 256 KiB — the size where frames straddle multiple reads and
the streaming ingest path carries the wire load (re-run post-fix; the
20 B row re-measured at 151 k, within noise of the original).
~7× CPython at small payloads, narrowing to ~3.3× at 16 KiB where
C-level `memcpy` dominates the Python stack. At 16 KiB duetto is echoing
~1.3 GB/s of payload through one shared core.

Architecture caveat: sync tungstenite (thread-per-connection) is its
documented server shape; the reactor-shaped Rust peer would be
tokio-websockets, which apt's rustc 1.75 cannot build (see analytical
section). Both contenders here got identical conditions.

### permessage-deflate

`load_test`'s deflate mode is excluded: it hardcodes
`server_will_compress = 0` and expects byte counts that only match a
uWS-specific configuration (decompress inbound, respond uncompressed),
so any RFC 7692 server that echoes compressed — duetto and `websockets`
alike — registers 0 msg/s. Substitute measurement with a neutral
generator (the same Python `websockets` client driving both servers,
50 connections, 4 KiB JSON-ish, deflate negotiated):

| Server | msg/s |
|---|---|
| duetto | 6,744 |
| `websockets` | 6,349 |

The Python *client* saturates the shared core first, so read this as
"both servers keep up with a saturated real-world client", with duetto 6%
ahead. The server-side deflate ceiling is the component number above.

## Correctness, cross-checked

- 5 unit suites green (RFC frame vectors, 16.8 M-case exhaustive UTF-8
  differential, handshake matrices, deflate bomb-cap, 26-test protocol
  conformance asserting wire close codes in both roles).
- `wsinterop` 11/11 over real TCP, including raw-socket violations:
  unmasked frame → 1002, invalid close code → 1002, fragmented ping →
  1002, invalid UTF-8 → 1007.
- Bidirectional cross-check vs Python `websockets` 16.0: text, multibyte,
  512 KiB binary, **fragmentation reassembly**, ping, clean close,
  deflate — plus four more raw violations (reserved opcode, oversize
  control, unnegotiated RSV1) answered with the right codes. duetto client
  also passes 5/5 against a tungstenite server.
- Not run: Autobahn (Python 2 only). The batteries above mirror its core
  cases; a full ~500-case run is the obvious next validation step on a
  dev machine.

## Analytical comparison (not run locally — documentation and published numbers)

| Library | Language | I/O shape | Masking | Spec posture |
|---|---|---|---|---|
| **duetto** | FreePascal | sans-I/O core; epoll server, blocking client | SSE2 / UInt64, in-place | strict; violations close with correct codes |
| tokio-websockets | Rust | tokio reactor | SIMD (AVX2/SSE2/NEON) | strict, passes Autobahn without relaxations |
| fastwebsockets | Rust | hyper/tokio | SIMD UTF-8 via simdutf8 | non-strict per tokio-websockets' bench notes, which also flag soundness caveats |
| tungstenite | Rust | sync (or tokio via wrapper) | scalar | popular baseline; non-strict per the same notes |
| websocket.zig | Zig | blocking and nonblocking modes | in-place unmask of caller's mutable buffer | comptime-checked handlers; Autobahn-tested |
| uWebSockets | C++ | epoll/uSockets, corked writes | SIMD | the de-facto speed reference |

Could not benchmark locally: tokio-websockets and current fastwebsockets
need a newer Rust than apt ships; Zig's toolchain domain isn't reachable
from this sandbox. websocket.zig's design reads closest to duetto — both
unmask in place in the caller's buffer and keep per-connection state
small; the difference is duetto's sans-I/O split, which is what made the
26-test conformance suite and the in-process round-trip bench possible
with zero sockets.

Published reference points, different hardware, not comparable to the
table above: tokio-websockets' bench README (Ryzen 9 7950X) shows
tokio-tungstenite well behind tokio-websockets/uWS with this same
load_test method; the wtx ws-bench suite ranks CPython `websockets`
slowest of six by a wide margin, which matches the 7× gap measured here.

## What I'd measure next

Multi-core hardware (separate generator and server boxes, or at minimum
pinned cores), p50/p99 latency rather than throughput alone, RSS at 10 k
idle connections, a full Autobahn run, TLS (`wss://`) throughput, and a
tokio-websockets build on a current toolchain as the proper Rust peer.
On the library side the remaining copies at large sizes are send-path
`OutAppend` and the assembly append — vectored I/O (`writev` of header +
caller payload) would remove the former for unmasked server sends.
