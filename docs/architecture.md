# Architecture

## Executive Summary

- duetto implements RFC 6455 (WebSocket v13) and RFC 7692 (permessage-deflate) in ~8,700 lines of FreePascal (library units; twice that with tests and programs).
- The heart is `WS.Protocol`, a **sans-I/O state machine** — one instance per connection, either role — that never touches a file descriptor.
- Every RFC rule lives in that one testable place; the blocking client, the epoll server, and the in-process benchmark all sit behind the same machine unchanged.
- Layers are strictly bottom-up: frame codec → UTF-8 → handshake → deflate → protocol machine → client / server.
- The server is a platform-neutral session layer over a completion-shaped **transport** seam (ADR-0001/0003): epoll on Linux and IOCP on Windows (native `wss://` over lwpt's memory-BIO accept API — OpenSSL on Linux, SChannel on Windows x64 and win32 — shared through `WS.Transport.TlsServer`), Network.framework on macOS (native `wss://` inside the platform stack). The client runs on POSIX and Windows (direct WinSock2) with TLS delegated to lwpt's `TransportSecurity`.
- The server bounds what one peer can cost: six `TWSServer` properties cap unsent output, connection count and session clocks, and one sweeper thread posts clock checks onto each connection's execution context (ADR-0005).

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
| `WS.Clock` | `WSMonotonicMs`, the monotonic millisecond clock behind every deadline (session clocks, close drains, TLS handshake budgets, accept backoff, the client's bounded read); `CLOCK_UPTIME_RAW` on macOS, where FPC 3.2.2's `GetTickCount64` is wall-clock |
| `WS.Frame` | header parse/encode, strict minimal-length rules; masking via byte loop / UInt64 / SSE2 |
| `WS.Utf8` | Höhrmann DFA with an 8-byte-word ASCII fast path; resumable across fragments |
| `WS.Handshake` | upgrade request/response both directions, `Sec-WebSocket-Accept`, deflate parameter negotiation |
| `WS.Url` | RFC 6455 §3 `ws://` / `wss://` URIs for the client: case-insensitive scheme, ASCII registered names, IPv4 and bracketed IPv6 literals, RFC 3986 userinfo accepted and never sent (RFC 6455 has no URI credentials), port 1–65535 with the scheme default when absent, the §3 resource name (`ws://h?x=1` requests `/?x=1`), fragments refused (§3), control characters and spaces refused in host, path and query, and the §4.1 `Host` value (brackets kept, port only when it is not the scheme default) |
| `WS.Deflate` | RFC 7692 over paszlib: raw deflate, sync flush, 4-byte tail, context takeover control, inflate output cap |
| `WS.Protocol` | the sans-I/O machine above |
| `WS.Client` | blocking client, `ws://` and `wss://` (TLS via lwpt's TransportSecurity); the URL goes through `WS.Url`, a refusal raising `EWSClient` before any socket exists, and the host resolves through `getaddrinfo` with `AF_UNSPEC` on every platform, each address tried in the resolver's order (an `AF_INET6` socket for an IPv6 one) under one shared `ConnectTimeoutMs` deadline; messages queue for `ReadMessage`, or go to an optional synchronous `OnMessage` inside the read that completed them, so a reply leaves ahead of a close that a later frame in the same read provokes; a failure after `Connect` (reset, dead peer, TLS error) never raises, it ends the connection (`Open` False, `ReadMessage` False / `wrrClosed`), while `Connect` raises only `EWSClient`; `ConnectTimeoutMs`, `HandshakeTimeoutMs` and `CloseTimeoutMs` (10 s, 10 s, 5 s by default) bound the TCP connect, the wait for the 101 and the wait for the close echo — over `wss://` the last two bound only the wait for the first ciphertext, and the TLS handshake itself stays unbounded until it can run on a non-blocking socket and lwpt can disarm its deadline afterwards; plaintext sends never raise `SIGPIPE` (`MSG_NOSIGNAL` on Linux, `SO_NOSIGPIPE` on Darwin; Linux `wss://` writes inside OpenSSL still can, duetto#79), `EINTR` is retried on plaintext sockets and on Linux `wss://` (lwpt's macOS and Windows TLS paths do not retry it), and a reconnect releases everything the previous connection held, its undrained queue included |
| `WS.Transport` | the completion-shaped transport contract (ADR-0001): submit sends/closes, receive data/lifecycle completions on the transport's execution context (ADR-0003); an optional gather send (ADR-0004: `SupportsGather` / `SubmitSendV`) that only a transport writing synchronously offers, letting the server hand frame header + caller payload to the socket without copying the payload into the out queue; also `WSParseBindAddress`, the strict IPv4/IPv6 literal parser every transport binds through (never a resolver) |
| `WS.Transport.PostQueue` | thread-safe FIFO behind the reactor transports' `SubmitPost` (cross-thread `Conn.Post` hand-off); the Network.framework transport posts straight onto its per-connection GCD queues instead |
| `WS.Transport.TlsServer` | platform-neutral per-connection server TLS over lwpt's memory-BIO accept API: handshake pump, accepted-prefix re-offer, input/output flow accounting, `close_notify` drain; used by the fd-owning transports only |
| `WS.Transport.Epoll` | Linux transport: nonblocking sockets, one shared 256 KB read buffer, a bounded number of reads per readiness event (level-triggered, so one busy peer cannot hold the loop), `EPOLLOUT` armed only while a connection has backlog, gather send via `sendmsg` on plaintext connections; native `wss://` through `WS.Transport.TlsServer`, with the handshake deadline, the inbound pre-handshake budget and the `EPOLLIN` pause/resume owned by the reactor; a reserve descriptor and an accept backoff for descriptor exhaustion |
| `WS.Transport.NetworkFramework` | macOS transport (ADR-0002): `nw_listener`/`nw_connection` C API, one serial dispatch queue per connection, native TLS via a PKCS#12 `SecIdentity` |
| `WS.Transport.Iocp` | Windows transport: one completion-port thread, `AcceptEx`/`WSARecv`/`WSASend` always armed overlapped, copy-on-send, outstanding-operation pinning for deferred frees; native `wss://` (x64 and win32, via lwpt's SChannel accept — no OpenSSL on Windows) through `WS.Transport.TlsServer`, with the handshake deadline, the inbound pre-handshake budget and the `WSARecv` suppress/resume owned by the completion loop; an accept backoff when the listener cannot be re-armed |
| `WS.Server` | platform-neutral session layer: handshake accumulation, protocol wiring, flush/backpressure policy over the transport seam; `SendText`/`SendBinary` return False when the transport dropped (and freed) the connection mid-flush, and `Conn.Post` is the any-thread hand-off for server-driven pushes (ADR-0003 amendment); `OnUpgradeRequest` receives a mutable `TWSUpgradeContext` before the 101 is queued and either vetoes the parsed upgrade (403, then close — no `OnOpen`/`OnClientClose`) or accepts it, its `UserData` landing on the connection before `OnOpen`; an exception escaping `OnOpen`, `OnMessage`, `OnClientClose` or a `Post` proc is contained on every transport (that connection closes with 1011 unless it is already closing, `OnError` reports it, `Run` and every other connection carry on); the constructors take an optional bind address (`''` = every interface; an IPv4 or IPv6 literal binds that one, no DNS); and six properties bound output, connections and session clocks, checked by one sweeper thread (see [Server resource bounds](#server-resource-bounds)) |

Units higher in the table never depend on units lower down. The programs in
`source/apps/` depend on the library, never the other way around.

## Server resource bounds

`WS.Server` bounds what one peer can cost the host through six `TWSServer`
properties. `MaxConnections` is checked on the accept path, before a
session connection exists (the `Run` thread on epoll and IOCP, the listener
queue on Network.framework), so a change applies to later accepts. The
other five are judged on each connection's own execution context
(ADR-0003). `MaxPendingOutput` is read on every flush. Each clock takes its
property's value when it is armed: `HandshakeTimeoutMs` at accept,
`CloseTimeoutMs` when a close or drain begins, `IdleTimeoutMs` and
`PingIntervalMs` when the connection opens and whenever the peer sends. A
change therefore never moves a deadline that is already armed. Set them all
before `Run`. [deployment.md](deployment.md#server-limits-for-production-hosts)
says which ones a production host should set.

| Property | Default | What it bounds | When it trips |
|---|---|---|---|
| `MaxPendingOutput` | 4 × the constructor's message cap `AMaxMessage` (16 MiB, so 64 MiB), at least 1 MiB; 0 = unbounded | protocol output one connection holds unsent because the peer is not reading | Judged on every flush. Crossing it drops the connection without a close frame. A connection already draining towards its drop is exempt: `CloseTimeoutMs` bounds that drain, and with `CloseTimeoutMs = 0` nothing in the session does. |
| `MaxConnections` | 0 = unbounded | live session connections, handshaking ones included | An accept past the cap is closed at once, before any session state exists: no handshake, no `OnOpen`, no `OnClientClose`. |
| `HandshakeTimeoutMs` | 10 s; 0 = never | time from accept until the 101 is handed to the transport | Silent drop; `OnOpen` never fired. On a TLS listener this clock also starts at accept, so it bounds TLS handshake and HTTP upgrade together. |
| `CloseTimeoutMs` | 10 s; 0 = never | time a peer gets to answer a Close, or to read what drains ahead of a drop (a 403, an `OnPlainRequest` answer, a protocol-error or 1011 close frame) | Drop. The budget is armed once per drain; peer traffic does not extend it. |
| `IdleTimeoutMs` | 0 = never | time without a single byte from the peer on an open connection | 1001 `idle timeout` is queued best effort, then the connection is dropped without waiting for the echo; `OnClientClose` fires. |
| `PingIntervalMs` | 0 = never | quiet time before the server pings the peer | One ping per quiet period. Any byte from the peer, a pong included, restarts the ping and idle clocks, so a peer that answers pings is not idle. |

The opening handshake has a fixed cap that is not a property:
`WS_MAX_HANDSHAKE` in `WS.Handshake`, 16 KiB of request header block
(request line through the terminating blank line). Frames a client
pipelines behind a complete block do not count towards it. A block past
the cap is answered with `431 Request Header Fields Too Large` (RFC 6585),
best effort, and the connection is dropped. It never opened, so neither
`OnOpen` nor `OnClientClose` fires. The search for the blank line resumes
where the previous read stopped, so a trickled request costs linear time.

A handler fault is bounded the same way. An exception escaping `OnOpen`,
`OnMessage`, `OnClientClose` or a `Post` proc is caught where the server
called the handler, on every transport. If the connection it escaped
from is still open, it queues 1011; one that is already closing gets no
1011. Either way it is dropped once its queued output is on the wire, or
when `CloseTimeoutMs` lapses for a peer that is not reading. `TWSServer.OnError`
reports the exception on the failing handler's execution context, and `Run`
and every other connection carry on. A raising `OnClientClose` has nothing
left to close and is only reported. `OnUpgradeRequest` and `OnPlainRequest`
are outside this policy: an exception there is a refusal.

### Session clocks and the sweeper

`HandshakeTimeoutMs`, `CloseTimeoutMs`, `IdleTimeoutMs` and `PingIntervalMs`
are session clocks. Each connection keeps its deadline and its ping due
time in `WSMonotonicMs` milliseconds and writes them only on its own
execution context. Each `TWSServer` owns one sweeper thread, started by the
constructor and joined first by `Destroy`. Every 100 ms (`SweepIntervalMs`)
it takes the registry lock, walks the live connections and compares each
one's earliest due time with the clock. For a connection that is due and
has no check queued, it posts `CheckClock` onto that connection's execution
context through the transport's `SubmitPost`, the cross-thread hand-off
behind `TWSConnection.Post`. The sweeper reads the due time without
synchronizing with the connection and may see a stale value: a stale
earlier value costs a spare check, and a stale later one defers the check
to a following sweep. `CheckClock` re-reads the clocks on the
connection's own context and does the work there: it drops a lapsed handshake, closes an
idle connection with 1001, drops a lapsed close or drain, or sends a due
ping. Clock events therefore keep ADR-0003's per-connection serialization
on every transport. [ADR-0005](adr/0005-session-clock-sweeper-and-close-drain-budget.md)
records this decision.

Two consequences follow. A clock acts up to one sweep interval late, or
later when a stale read defers its check, plus however long the
connection's execution context is busy; on epoll and IOCP that context is
the one `Run` thread every connection shares. And the
registry lock, otherwise taken on accept, on close and by each `Post`, is
also held for one walk of the live connections every 100 ms, whether or not
any clock is armed.

### Transport bounds

- **Descriptor exhaustion (epoll).** A level-triggered listener that cannot
  accept stays readable, so an accept failure that is only returned would
  spin `epoll_wait`. `WS.Transport.Epoll` holds one reserve descriptor open
  on `/dev/null`. When `accept` fails with `EMFILE` or `ENFILE`, it closes
  the reserve, accepts the peer at the head of the backlog, closes that peer
  at once and reopens the reserve. The backlog is shed rather than spun on,
  at most 64 peers per listener event (`MaxShedPerEvent`). When the reserve
  cannot be had either, or accept fails with `ENOBUFS` or `ENOMEM`, the
  listener leaves the epoll interest set for 100 ms (`AcceptBackoffMs`) and
  `Run` re-arms it; a re-arm that fails retries after another 100 ms.
- **Accept backoff (IOCP).** When `WS.Transport.Iocp` cannot create an
  accept socket, or `AcceptEx` fails with anything other than a reset
  backlog entry (`WSAENOBUFS`, `WSAEMFILE` and the like), the listener stays
  unarmed for 100 ms and the completion loop re-arms it, instead of raising
  out of `Run`.
- **Close-drain budget.** `TWSTransportTls.HandshakeDeadlineMs` (default
  10 s) bounds the TLS handshake on the fd-owning transports and is reused,
  on all three transports, as the time a close that is still delivering its
  final bytes may hold the connection after the session dropped it. On
  epoll it bounds the TLS close drain (`close_notify` out, then FIN and the
  peer's EOF); a plaintext epoll connection closes at once and has no
  drain. On IOCP it bounds graceful closes, TLS or plaintext: the
  `close_notify` drain, a plaintext close deferred behind a send still in
  flight, and the wait for the peer's EOF after FIN. On both, the
  transport's 100 ms deadline sweep closes the socket abortively when the
  budget lapses. One IOCP wait is not bounded: when a TLS connection whose
  handshake finished is closed while a send is in flight, the drain
  deadline starts only once that send completes, so a peer that stops
  reading holds the socket until then. On Network.framework the budget
  bounds any close deferred behind an in-flight send, TLS or not, and a
  dispatch timer on the connection's queue cancels the connection when it
  lapses. IOCP and Network.framework read the field with `Enabled = False`
  too.

The transport budget starts only after the session drops the connection.
A peer that stops reading can hold a descriptor for up to `CloseTimeoutMs`
in the session and then up to `HandshakeDeadlineMs` in the transport's
close drain, except in the IOCP TLS case above, where the wait for the
in-flight send comes first and has no bound. With `CloseTimeoutMs = 0` the
session stage has no bound, so the transport budget never starts for a
peer that never reads. Connections
in that transport drain are already out of the session registry, so
`MaxConnections` no longer counts them.

## Validation strategy

Four nets, from innermost to outermost:

1. **Co-located unit suites** (`lwpt test`, one per `source/units/*.Test.pas`): RFC §5.7 frame
   vectors and strictness, an exhaustive 16.8M-case UTF-8 differential,
   handshake acceptance/rejection matrices, deflate round-trips with
   takeover and bomb-cap checks, a 26-test protocol conformance suite
   asserting *wire* close codes for the violation matrix in both roles,
   and a `WS.Transport.PostQueue` suite covering FIFO order through
   drain, the stop rendezvous (pending handed back exactly once, pushes
   refused afterwards), and per-producer order under contention, and a `WS.Transport.TlsServer` suite covering the flow-control policy
   (independent input/output capacities, low-water rules, defaults) and
   the accepted-prefix carry buffer (order, re-offer, compaction), and a
   `WS.Transport` suite pinning the bind-address literal parser (strict
   dotted-quad, RFC 4291 IPv6 forms, and a rejection matrix that names
   the offending input) and the default gather send every transport
   inherits, a `WS.Url` suite covering every accepted URL form (IPv6
   literals, userinfo, empty and boundary ports, a query without a path,
   the scheme-relative `Host` port rule) and rejection tables (fragments,
   CR/LF and other control characters, bad ports, hosts and schemes), plus a protocol direct-send suite (when a frame may bypass
   the out queue, and that exactly the untaken tail is queued), and a
   `WS.Clock` suite checking that the deadline clock never runs
   backwards and advances in milliseconds.
2. **`wsinterop`**: own client ↔ own server over real TCP, plus raw-socket
   violations (unmasked frame → 1002, invalid close code → 1002, fragmented
   ping → 1002, invalid UTF-8 → 1007), a client-delivery section (a raw
   peer writes a valid message, an RSV2 frame and a ping in one send,
   both after the 101 and glued to it; the client's `OnMessage` echo must
   leave before its 1002 close, with nothing after it; `Close` from the
   handler completes, `ReadMessage` from it raises), a client-robustness
   section (sends into a peer that hung up and reset, with `SIGPIPE`
   back at its default action; connect, handshake and close timeouts
   against a full backlog, a silent listener and a peer that never
   echoes; a TLS handshake failure surfacing as `EWSClient`; a blocking
   read interrupted by signals; reconnects after undrained messages and
   after a raising `OnMessage`), a client-URL section (URLs carrying
   CR/LF refused before connecting, userinfo never sent, a query without
   a path requesting `/?query` and the `Host` port seen by a raw peer;
   `ws://[::1]:port/` echoing through a server bound to `::1` with the
   literal bracketed in `Host`, or a skip line where IPv6 loopback is
   unavailable), an upgrade-hook
   section (a server
   bound to `127.0.0.1` explicitly whose `OnUpgradeRequest` refuses one
   `Origin` with a 403 — no `OnOpen`, no `OnClientClose` — treats a
   raising hook the same way, and sets a `UserData` that `OnOpen` finds
   on that same connection), a handler-fault section (a raising
   `OnMessage`, `OnOpen` or `Post` proc costs only its connection: 1011,
   reported to `OnError`, a bystander still echoes; a raising
   `OnClientClose` is only reported), a handshake-size section (a request
   header block past the 16 KiB cap gets `431 Request Header Fields Too
   Large`, while a block at the cap with frames pipelined behind it and a
   client path longer than 2 KiB still upgrade), a limits section on a
   server with tight bounds (a stalled handshake, a peer that never
   answers a Close, a silent peer closed with 1001, a quiet peer kept open
   by keepalive pings, a non-reading flood past `MaxPendingOutput`, a
   Close whose echo drains under `CloseTimeoutMs` while the peer keeps
   sending (Linux), a third connection at `MaxConnections = 2`, and every `OnOpen`
   paired with one `OnClientClose`), a
   plaintext egress-backpressure probe
   (a stalled reader backs the server's egress up — on Linux forcing the
   epoll gather write short mid-message; eight 1 MiB echoes must still
   arrive intact and in order), and — on Linux — a `wss://` section
   against a TLS listener built from a runtime-generated identity
   (handshake, echo, flow-control windows, `close_notify`, handshake
   deadline, inbound pre-handshake budget, and a client whose TLS stream
   breaks mid-session through a garbage record or a reset).
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
