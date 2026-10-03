# ADR 0005 — Session clocks on one sweeper; one close-drain budget for every transport

Date: 2026-10-03
Status: accepted. Supersedes in part [ADR-0003](0003-transport-execution-context.md):
its statement that the session layer's only lock is taken on accept and
close.

## Context

Server hardening (#34) gave `WS.Server` four session clocks:
`HandshakeTimeoutMs`, `CloseTimeoutMs`, `IdleTimeoutMs` and
`PingIntervalMs`. A clock has to fire when nothing else happens. A peer
that connects and says nothing, or stops reading during a close, produces
no completion, so the clocks cannot be judged only when a completion
arrives.

Whatever judges a clock also acts on the connection: it drops it, queues
a close frame or sends a ping. ADR-0003 confines that work to the
connection's execution context, which is the `Run` thread on epoll and
IOCP and a serial dispatch queue per connection on Network.framework. The
transport contract (ADR-0001) has no timer operation. Its only
cross-thread entry point is `SubmitPost`, which runs a proc on a named
connection's execution context, serialized with that connection's other
completions.

The transports had a second, older problem of the same kind. A close that
still has bytes to deliver (TLS `close_notify` on epoll and IOCP, a close
deferred behind an in-flight send on Network.framework) can wait on a peer
that never reads. The epoll and IOCP transports already bounded their TLS
close drain with `TWSTransportTls.HandshakeDeadlineMs`. Network.framework
had no bound, and a non-reading peer pinned its connection until shutdown.

## Decision

**Session clocks are checked by one sweeper thread per server and posted
per connection.** `TWSServer` owns one thread, started by its constructor
and joined first by its destructor. Every 100 ms it takes the registry
lock and compares each live connection's earliest due time with
`WSMonotonicMs`. For each connection that is due and has no check queued,
it posts a check through `SubmitPost`. The check re-reads the clocks on
the connection's own context and does the dropping, closing or pinging
there. The sweeper reads one due time per connection, racily by design (a
stale value costs a spare post or defers the check to a later sweep). The
only connection field it writes is the flag that marks a check as queued.

This keeps every clock action inside ADR-0003's per-connection
serialization on all three transports, with no transport change and no
new transport operation. The alternatives each needed one of those: a
timer operation added to the transport contract and implemented three
times, or clock checks run on a thread other than the connection's
context.

**The transport close-drain budget is one field shared by all three
transports.** `TWSTransportTls.HandshakeDeadlineMs` (default 10 s) bounds
how long a close that is still delivering its final bytes may hold a
connection after the session dropped it:

- epoll and IOCP: the TLS close drain;
- Network.framework: any close deferred behind an in-flight send, with
  `Enabled = False` too.

Waiting for a quiet peer to finish a close is the same problem as waiting
for a quiet peer to finish a TLS handshake, on the same time scale. A
second field would add configuration without a distinct decision behind
it. These deadlines stay with the transports, not the sweeper: once the
session has dropped a connection it holds no object to post a check to.

## Consequences

- The registry lock is no longer taken on accept and close only. Each
  `Post` takes it for its rendezvous (the ADR-0003 amendment), and the
  sweeper holds it for one walk of the live connections every 100 ms,
  whether or not any clock is armed. The session layer's receive and
  send paths still take no lock.
- A clock acts up to one sweep interval late, plus however long the
  connection's execution context is busy. On epoll and IOCP that context
  is the one `Run` thread, so a slow handler delays every connection's
  clock checks.
- Each server costs one more thread, which runs from construction to
  destruction even when every clock is off.
- The close-drain budget lives in the TLS record under a handshake name.
  A plaintext listener on macOS sets it by passing a `TWSTransportTls`
  with `Enabled = False` to the TLS constructor overload.
- A peer that stops reading can hold a descriptor for up to
  `CloseTimeoutMs` in the session, then up to `HandshakeDeadlineMs` in the
  transport's close drain.
- The IOCP plaintext graceful close is not covered by the shared budget
  yet; a peer that never closes holds the socket until `Shutdown`
  ([#46](https://github.com/frostney/duetto/issues/46)).
