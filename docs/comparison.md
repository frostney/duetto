# duetto vs Rust, Python, C++ — measured where possible, honest where not

Everything in the **measured** sections ran on one machine on
2026-09-25. Everything in the **analytical** section is from
documentation and published benchmarks, clearly labelled.

## Environment (read this first)

AMD Ryzen AI MAX+ 395 (Zen 5, 16 cores / 32 threads), Linux 7.0, loopback
only. The machine is shared with other work: runs were started only
after the 1-minute load average had stayed under 1 for two minutes, and
differences under ~3% should be read as noise. duetto: FPC 3.2.2,
`lwpt build --mode release` (`-O4 -dPRODUCTION`). tungstenite 0.21.0
built by rustc 1.98.1 (release, LTO). CPython 3.12.3 with `websockets`
16.0. uWebSockets `load_test` and `EchoServer` from uWebSockets 589c282
(gcc `-O3`, no SSL, epoll).

duetto's component numbers come from `./build/wsbench` and the
cross-implementation tables from `tools/benchmatrix.sh` (see
[tooling.md](tooling.md#benchmarks)). The stage-by-stage table, the
uWebSockets reference rows, the io_uring check and the starvation probe
used one-off scripts with the same `load_test` invocation and pinning.

Two pinnings, both with `taskset`:

- **Separate cores** — server on CPU 2, generator on CPU 4 (two physical
  cores). The generator no longer competes with the server; this is the
  shape of a real deployment and the headline table below.
- **Shared core** — server and generator both on CPU 2. The methodology
  of the previous edition of this page (a 1-vCPU sandbox); kept because
  it stresses scheduling behaviour the separate-core run hides.

`load_test` reports one throughput sample every 4 s and the first covers
the ramp-up; each score below is the best of the two full 4-second
windows that follow it.

## Component benchmarks (duetto internals, `wsbench`)

Median of three release runs.

| Subject | Result |
|---|---|
| Masking — naive byte loop | 3.3 GB/s |
| Masking — UInt64 XOR (the portable path) | 57.7 GB/s |
| Masking — SSE2 | 92.0 GB/s |
| Payload copy, 16 KiB — RTL `Move` / `MovePayload` (libc `memcpy`) | 45.3 / 185.9 GB/s |
| Payload copy, 256 KiB — RTL `Move` / `MovePayload` | 43.3 / 150.5 GB/s |
| Masked chunk into a buffer, 16 KiB — copy then unmask / `ApplyMaskCopy` | 61.4 / 90.2 GB/s |
| Masked chunk into a buffer, 256 KiB — copy then unmask / `ApplyMaskCopy` | 59.7 / 97.5 GB/s |
| Frame header parse (mixed 7/16-bit lengths) | 174 M frames/s |
| UTF-8 — ASCII fast path | 6.0 GB/s |
| UTF-8 — pure Höhrmann DFA | 0.95 GB/s |
| UTF-8 — mixed CJK/ASCII | 0.75 GB/s |
| Opening handshake (parse + respond) | 773 k/s (1.3 µs each) |
| Deflate compress (JSON-ish, ratio 6.2%) | 267 MB/s |
| Inflate | 1.83 GB/s |

The UInt64 loop is the only unmask path on aarch64, macOS and Windows.
Its previous form counted a length down in 32-byte passes, and its speed
on this CPU depended on things outside its code: where it was placed (a
static harness shifting it through eight 8-byte offsets read 35.6–52.5
GB/s) and how the binary was linked (the same bytes at the same address
read ~52 GB/s static and ~36 with libc linked). The current loop runs 64
bytes per pass up to an end pointer and read 52–58 GB/s in every one of
those configurations. The main build before the series happens to read
36.8 GB/s with the old loop.

Full in-process round trip — two `TWSProtocol` machines piped
back-to-back, so every message is masked, parsed, validated and
unmasked twice, no sockets. Median of three, before and after the
2026-09 optimisation series:

| Payload | Before | After | Change |
|---|---|---|---|
| 64 B | 12.29 M/s | 13.01 M/s | +6% |
| 1 KiB | 5.68 M/s | 8.40 M/s | +48% |
| 16 KiB | 509 k/s | 956 k/s | +88% |
| 256 KiB | 19.8 k/s | 30.3 k/s | +53% (25.0–31.3 k/s run to run) |

"Before" is main with `wsbench`'s clock fixed. The previous edition's
2.35 M round trips/s at 64 B was mostly its timer: the loop read
`SysUtils.Now` every iteration, and on this machine that build read
3.1 M/s where the fixed clock reads 12.3 M/s. (FPC's `clock_gettime` is
a raw syscall, so even a precise clock read every iteration costs ~40%
at 64 B; the loop now reads it once per 256 iterations.)

## End-to-end echo (uWebSockets `load_test`, 100 connections)

`load_test` opens 100 connections, each ping-ponging one message; plain
echo, deflate off. uWebSockets' own C++ `EchoServer` is the reference
row.

**Separate cores:**

| Payload | duetto | tungstenite 0.21 | `websockets` 16.0 | uWebSockets (reference) |
|---|---|---|---|---|
| 20 B | **621,651 msg/s** | 448,870 | 85,525 | 715,243 |
| 1 KiB | **606,502 msg/s** | 432,624 | 79,432 | 696,182 |
| 16 KiB | **417,934 msg/s** | 224,825 | 83,380 | 439,722 |
| 256 KiB | **22,426 msg/s** | 10,578 | 12,386 | 25,206 |

duetto runs at 1.38× tungstenite at 20 B, 1.40× at 1 KiB, 1.86× at
16 KiB and 2.12× at 256 KiB, and at 87–95% of uWebSockets. At 16 KiB it
echoes ~6.8 GB/s of payload each way on one server core. The
`websockets` 16 KiB score comes from a run whose last window was
disturbed (65.7 k against 78.6 k and 83.4 k); duetto's and
tungstenite's windows in the same run agree within 1.5%.

**Shared core:**

| Payload | duetto | tungstenite 0.21 | `websockets` 16.0 | uWebSockets (reference) |
|---|---|---|---|---|
| 20 B | 247,301 msg/s | 249,020 | 61,132 | 265,352 |
| 1 KiB | 240,216 msg/s | 242,984 | 64,366 | 254,366 |
| 16 KiB | **186,345 msg/s** | 156,345 | 64,271 | 192,791 |
| 256 KiB | **18,730 msg/s** | 8,316 | 9,215 | 21,946 |

At 20 B and 1 KiB duetto and tungstenite are within noise of each
other; uWebSockets is 6–7% higher. The previous edition's "~1.4×
tungstenite" was measured in this setup on a 1-vCPU Xeon; on this
machine the two are indistinguishable there.

Architecture caveat: sync tungstenite (thread-per-connection) is its
documented server shape; the reactor-shaped Rust peer would be
tokio-websockets, not measured here (see the analytical section).

### The 2026-09 optimisation series

Separate cores, one run per build, a separate run from the headline
table above:

| Build | 20 B | 1 KiB | 16 KiB | 256 KiB |
|---|---|---|---|---|
| main before the series | 576,621 | 549,418 | 315,905 | 16,693 |
| + epoll: bounded reads per readiness event | 618,550 | 588,452 | 323,907 | 17,068 |
| main + payload-copy series (no read bound) | 573,232 | 556,398 | 377,995 | 20,707 |
| … + gather-write sends (no read bound) | 562,833 | 553,352 | 402,758 | 22,370 |
| everything | **626,842** | **602,744** | **413,101** | **24,548** |
| change | +9% | +10% | +31% | +47% |

What each stage does:

- **Bounded reads** — the epoll reactor stopped reading a socket until
  `EAGAIN`: it stops at a short read (the final `recv` was a wasted
  syscall per message) or after four full 256 KB reads (a flooding peer
  could hold the loop indefinitely). With one Python client flooding
  64 KiB frames, a second connection's ping echo took p50 40.7 ms /
  max 537 ms on main and p50 0.3 ms / max 0.3 ms with the bound (server
  on CPU 2, clients on CPUs 4–7).
- **Payload copies** — a complete, unfragmented, uncompressed frame is
  delivered from the read buffer instead of being copied into the
  assembly buffer; masked chunks that do need assembling (and a
  client's outgoing payload) are unmasked while copying rather than
  copied then unmasked; the remaining payload copies use libc `memcpy`
  on Unix, 3–4× faster than the RTL's `Move` here.
- **Gather-write sends** — when nothing is queued, a server frame of
  1 KiB or more goes out as one `sendmsg` of header + the caller's
  buffer, skipping the copy into the out queue (ADR-0004; epoll only).

The read bound has a price in the shared-core setup, measured in the
same session:

| Build (shared core) | 16 KiB | 256 KiB |
|---|---|---|
| main before the series | 174,978 | 21,963 |
| + bounded reads alone | 163,094 (−7%) | 13,946 (−37%) |
| everything | 186,587 (+7%) | 18,361 (−16%) |

With the generator on the server's core, main's drain-to-`EAGAIN` loop
stayed on one hot connection: the generator ran on each echo, wrote the
next frame, and the loop read it straight away (instrumented: 9
`epoll_wait` calls in 4 s at 256 KiB). The bounded loop walks all 100
connections per batch instead, which loses locality for large payloads.
Reading to `EAGAIN` under the same four-read cap recovers most of it but
gives back the separate-core gains (−9% at 20 B and 1 KiB); size
thresholds on the short read (8, 32, 64 KiB) did not help, and a variant
that re-reads only after a full read recovers about 40% of the 256 KiB
loss. The separate-core behaviour was kept: remote peers never share the
server's core. uSockets, under uWebSockets, also stops at a short read
(with no cap on full reads).

### io_uring (measured, not pursued)

uWebSockets' own `EchoServer` on its io_uring backend (liburing, same
commit) against its epoll build, separate cores, same session: +5.6% at
20 B (747,143 vs 707,594), +10.5% at 1 KiB (759,608 vs 687,467); the
io_uring backend crashed at 16 KiB and above. A single-digit gain for a
new transport did not justify the work.

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
| Separate cores | 46,340 msg/s | 45,639 |
| Shared core | 25,252 msg/s | 22,678 |

The Python *client* is the ceiling in both setups, so read this as
"both servers keep up with a saturated real-world client". The
server-side deflate ceiling is the component number above.

## Correctness, cross-checked

- Every co-located unit suite green — eight at the time of measurement:
  frame (RFC §5.7 vectors, strictness, masking and copy equivalence),
  UTF-8 (16.8 M-case exhaustive differential), handshake, deflate
  (including the bomb cap), protocol (conformance with wire close codes
  in both roles, payload delivery, direct send), transport (bind
  literals, gather default), TLS server flow control, and the post
  queue.
- `wsinterop` over real TCP, including raw-socket violations (unmasked
  frame → 1002, invalid close code → 1002, fragmented ping → 1002,
  invalid UTF-8 → 1007) and an egress-backpressure probe.
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
here at 20 B and 1 KiB on separate cores (5× at 16 KiB).

## What I'd measure next

p50/p99 latency rather than throughput alone, RSS at 10 k idle
connections, TLS (`wss://`) throughput, tokio-websockets as the
reactor-shaped Rust peer, and the macOS / Windows transports (every
socket number above is epoll; the gather send is epoll-only and
`MovePayload` is RTL `Move` on Windows). Also the portable UInt64 loop
on aarch64, and whether the shared-core large-payload cost of the read
bound shows up anywhere outside a loopback benchmark.
