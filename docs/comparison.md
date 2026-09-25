# duetto vs Rust, Python, C++ — measured where possible, honest where not

Everything in the **measured** sections ran on one machine on
2026-09-25. Everything in the **analytical** section is from
documentation and published benchmarks, clearly labelled.

## Environment (read this first)

AMD Ryzen AI MAX+ 395 (Zen 5, 16 cores / 32 threads), Linux 7.0, loopback
only; other interactive sessions were running (load average ~2), so
treat differences under ~3% as noise. duetto: FPC 3.2.2,
`lwpt build --mode release` (`-O4 -dPRODUCTION`). tungstenite 0.21.0
built by rustc 1.98.1 (release, LTO). CPython 3.12.3 with `websockets`
16.0. uWebSockets `load_test` and `EchoServer` from uWebSockets 589c282
(gcc `-O3`, no SSL, epoll). Every number here comes from the tools in
this repo: `./build/wsbench` and `tools/benchmatrix.sh` (see
[tooling.md](tooling.md#benchmarks)).

Two pinnings, both with `taskset`:

- **Separate cores** — server on CPU 2, generator on CPU 4 (two physical
  cores). The generator no longer competes with the server; this is the
  shape of a real deployment and the headline table below.
- **Shared core** — server and generator both on CPU 2. The methodology
  of the previous edition of this page (a 1-vCPU sandbox); kept because
  it stresses scheduling behaviour the separate-core run hides.

## Component benchmarks (duetto internals, `wsbench`)

Median of three release runs.

| Subject | Result |
|---|---|
| Masking — naive byte loop | 3.3 GB/s |
| Masking — UInt64 XOR | 36.6 GB/s (52–54 GB/s in other builds — see below) |
| Masking — SSE2 | 87.7 GB/s |
| Payload copy, 16 KiB — RTL `Move` / `MovePayload` (libc `memcpy`) | 44.9 / 185.9 GB/s |
| Payload copy, 256 KiB — RTL `Move` / `MovePayload` | 43.6 / 150.3 GB/s |
| Masked chunk into a buffer, 16 KiB — copy then unmask / `ApplyMaskCopy` | 61.9 / 94.2 GB/s |
| Masked chunk into a buffer, 256 KiB — copy then unmask / `ApplyMaskCopy` | 59.3 / 97.6 GB/s |
| Frame header parse (mixed 7/16-bit lengths) | 120–165 M frames/s (noisy on this host) |
| UTF-8 — ASCII fast path | 5.4 GB/s |
| UTF-8 — pure Höhrmann DFA | 0.95 GB/s |
| UTF-8 — mixed CJK/ASCII | 0.70 GB/s |
| Opening handshake (parse + respond) | 785 k/s (1.3 µs each) |
| Deflate compress (JSON-ish, ratio 6.2%) | 274 MB/s |
| Inflate | 1.82 GB/s |

The UInt64 masking loop is not the path x86_64 Linux takes for anything
over 15 bytes (SSE2 is), but it is the portable one. Its speed on this
CPU depends on where the loop lands: the same source measures 52–54
GB/s in builds where it happens to sit well, 36 GB/s in the release
build above, and 52 GB/s again when that build adds
`{$codealign loop=32}` (but not `loop=64`). That is layout luck, not a
code change, and a global alignment directive tuned to one CPU was not
adopted.

Full in-process round trip — two `TWSProtocol` machines piped
back-to-back, so every message is masked, parsed, validated and
unmasked twice, no sockets. Median of three, before and after the
2026-09 optimisation series:

| Payload | Before | After | Change |
|---|---|---|---|
| 64 B | 7.11 M/s | 7.46 M/s | +5% |
| 1 KiB | 4.20 M/s | 5.62 M/s | +34% |
| 16 KiB | 484 k/s | 897 k/s | +85% |
| 256 KiB | 19.6 k/s | 29.6 k/s | +51% (25–31 k/s run to run) |

The "before" column is main with `wsbench`'s clock fixed. The previous
edition's 2.35 M round trips/s at 64 B was mostly its own timer: the loop
called `SysUtils.Now`, a calendar conversion, on every iteration.

## End-to-end echo (uWebSockets `load_test`, 100 connections)

`load_test` opens 100 connections, each ping-ponging one message; best
steady 4-second window of three, plain echo, deflate off. uWebSockets'
own C++ `EchoServer` is the reference row.

**Separate cores:**

| Payload | duetto | tungstenite 0.21 | `websockets` 16.0 | uWebSockets (reference) |
|---|---|---|---|---|
| 20 B | **620,030 msg/s** | 445,120 | 82,609 | 706,268 |
| 1 KiB | **595,840 msg/s** | 429,873 | 81,989 | 691,871 |
| 16 KiB | **414,922 msg/s** | 224,368 | 83,056 | 443,440 |
| 256 KiB | **23,532 msg/s** | 10,572 | 12,948 | 26,057 |

duetto runs at 1.39× tungstenite at 20 B and 1 KiB, 1.85× at 16 KiB and
2.23× at 256 KiB, and at 86–94% of uWebSockets throughout. At 16 KiB it
echoes ~6.8 GB/s of payload each way on one server core.

**Shared core:**

| Payload | duetto | tungstenite 0.21 | `websockets` 16.0 | uWebSockets (reference) |
|---|---|---|---|---|
| 20 B | 247,396 msg/s | 248,581 | 66,703 | 265,436 |
| 1 KiB | 241,398 msg/s | 240,771 | 62,918 | 253,498 |
| 16 KiB | **185,834 msg/s** | 155,540 | 64,526 | 194,308 |
| 256 KiB | **18,702 msg/s** | 8,332 | 8,894 | 21,932 |

At 20 B and 1 KiB every native server lands at ~250 k: the generator
sharing the core is the ceiling, not the server. The previous edition's
"~1.4× tungstenite" was measured in this setup on a 1-vCPU Xeon;
on this machine the two are indistinguishable there.

Architecture caveat: sync tungstenite (thread-per-connection) is its
documented server shape; the reactor-shaped Rust peer would be
tokio-websockets, not measured here (see the analytical section).

### The 2026-09 optimisation series

Separate cores, one run per build, each build a stage of the series:

| Build | 20 B | 1 KiB | 16 KiB | 256 KiB |
|---|---|---|---|---|
| main before the series | 572,833 | 543,504 | 305,838 | 16,646 |
| + epoll: bounded reads per readiness event | 619,118 | 589,580 | 323,835 | 16,799 |
| main + payload-copy series (no read bound) | 558,658 | 547,753 | 371,657 | 20,512 |
| … + gather-write sends (no read bound) | 566,485 | 556,086 | 400,987 | 22,218 |
| everything | **625,301** | **605,518** | **415,248** | **23,437** |
| change | +9% | +11% | +36% | +41% |

What each stage does:

- **Bounded reads** — the epoll reactor stopped reading a socket until
  `EAGAIN`: it stops at a short read (the final `recv` was a wasted
  syscall per message) or after four full 256 KB reads (a flooding peer
  could hold the loop indefinitely; a second connection's echo latency
  under one flooding client went from p50 25.6 ms to 0.3 ms).
- **Payload copies** — a complete, unfragmented, uncompressed frame is
  delivered from the read buffer instead of being copied into the
  assembly buffer; masked chunks that do need assembling (and a
  client's outgoing payload) are unmasked while copying rather than
  copied then unmasked; the remaining payload copies use libc `memcpy`
  on Unix, 3–4× faster than the RTL's `Move` here.
- **Gather-write sends** — when nothing is queued, a server frame of
  1 KiB or more goes out as one `sendmsg` of header + the caller's
  buffer, skipping the copy into the out queue (ADR-0004; epoll only).

The read bound has a price in the shared-core setup: at 256 KiB the
final build does 18.9 k msg/s against main's 22.0 k (16 KiB is +10%).
With server and generator on one core, a large `recv` frees window,
the sender's queued data lands during the same syscall, and a
short read is no longer "drained". Reading to `EAGAIN` under the same
four-read cap recovers most of it (21.2 k) but gives back the
separate-core gains (−9% at 20 B and 1 KiB, −5% at 16 KiB); size
thresholds on the short read (8, 32, 64 KiB) did not help. The
separate-core behaviour was kept. uWebSockets, which also reads once per
readiness event, does 21.9 k in the same setup.

### io_uring (measured, not pursued)

uWebSockets' own `EchoServer` on its io_uring backend (liburing, same
commit) against its epoll build, separate cores: +6.3% at 20 B
(747,832 vs 703,616), +9.3% at 1 KiB (755,328 vs 690,826); the io_uring
backend crashed at 16 KiB and above. A single-digit gain for a new
transport did not justify the work.

### permessage-deflate

`load_test`'s deflate mode is excluded: it hardcodes
`server_will_compress = 0` and expects byte counts that only match a
uWS-specific configuration (decompress inbound, respond uncompressed),
so any RFC 7692 server that echoes compressed — duetto and `websockets`
alike — registers 0 msg/s. Substitute measurement with a neutral
generator (`tools/deflbench.py`: the same Python `websockets` client
driving both servers, 50 connections, 4 KiB JSON-ish, deflate
negotiated):

| Pinning | duetto | `websockets` |
|---|---|---|
| Separate cores | 46,145 msg/s | 45,273 |
| Shared core | 23,292 msg/s | 22,779 |

The Python *client* is the ceiling in both setups, so read this as
"both servers keep up with a saturated real-world client". The
server-side deflate ceiling is the component number above.

## Correctness, cross-checked

- 8 unit suites green (RFC frame vectors, 16.8 M-case exhaustive UTF-8
  differential, handshake matrices, deflate bomb-cap, protocol
  conformance asserting wire close codes in both roles, payload-delivery
  and direct-send suites, transport and TLS flow-control suites).
- `wsinterop` over real TCP, including raw-socket violations (unmasked
  frame → 1002, invalid close code → 1002, fragmented ping → 1002,
  invalid UTF-8 → 1007), an egress-backpressure probe and a
  close-handler section.
- Bidirectional cross-check vs Python `websockets` 16.0
  (`tools/crosscheck.py`): text, multibyte, 512 KiB binary,
  fragmentation reassembly, ping, clean close, deflate, plus raw
  violations answered with the right codes.
- Autobahn testsuite, both directions, run natively on this machine for
  the measured build (CI runs it via Docker on every push to main):
  fuzzingclient vs `wsecho` — 1034 cases, 812 OK, 6 informational,
  216 unimplemented (the deflate cases of the no-deflate agent);
  fuzzingserver vs `wsautobahn` — 1034 cases, 798 OK, 14 non-strict,
  6 informational, 216 unimplemented. Every case acceptable under
  `tools/autobahn-check.py`.

## Analytical comparison (not run locally — documentation and published numbers)

| Library | Language | I/O shape | Masking | Spec posture |
|---|---|---|---|---|
| **duetto** | FreePascal | sans-I/O core; epoll / IOCP / Network.framework server, blocking client | SSE2 / UInt64, in place or fused with the copy | strict; violations close with correct codes |
| tokio-websockets | Rust | tokio reactor | SIMD (AVX2/SSE2/NEON) | strict, passes Autobahn without relaxations |
| fastwebsockets | Rust | hyper/tokio | SIMD UTF-8 via simdutf8 | non-strict per tokio-websockets' bench notes, which also flag soundness caveats |
| tungstenite | Rust | sync (or tokio via wrapper) | scalar | popular baseline; non-strict per the same notes |
| websocket.zig | Zig | blocking and nonblocking modes | in-place unmask of caller's mutable buffer | comptime-checked handlers; Autobahn-tested |
| uWebSockets | C++ | epoll/uSockets, corked writes | SIMD | the de-facto speed reference (measured above) |

Not measured here: tokio-websockets and fastwebsockets (a current
toolchain could build them now; this round did not), websocket.zig.
websocket.zig's design reads closest to duetto — both unmask in place
in the caller's buffer and keep per-connection state small; the
difference is duetto's sans-I/O split, which is what makes the
conformance suites and the in-process round-trip bench possible with
zero sockets.

Published reference points, different hardware, not comparable to the
tables above: tokio-websockets' bench README (Ryzen 9 7950X) shows
tokio-tungstenite well behind tokio-websockets/uWS with this same
load_test method; the wtx ws-bench suite ranks CPython `websockets`
slowest of six by a wide margin, which matches the ~7× gap measured
here at 20 B and 1 KiB (5× at 16 KiB).

## What I'd measure next

p50/p99 latency rather than throughput alone, RSS at 10 k idle
connections, TLS (`wss://`) throughput, tokio-websockets as the
reactor-shaped Rust peer, and the macOS / Windows transports (every
socket number above is epoll; the gather send is epoll-only and
`MovePayload` is RTL `Move` on Windows). Also the portable UInt64
masking loop on aarch64, where its placement sensitivity may look
different, and whether the shared-core large-payload cost of the read
bound shows up anywhere outside a loopback benchmark.
