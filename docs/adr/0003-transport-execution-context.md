# ADR 0003 — Callbacks run on the transport's execution context

Date: 2026-07-19
Status: accepted

## Context

The epoll reactor delivered every callback on the thread that called
`TWSServer.Run`, and consumers silently relied on that. Network.framework
delivers callbacks on GCD dispatch queues — threads Apple owns. Marshaling
every completion back to the Run thread (a completion mailbox) would
preserve the old contract at the cost of a cross-thread handoff per
completion; the maintainer chose native delivery with maximum initial
parallelism instead: macOS is a first-class performance platform, not a
development convenience.

## Decision

Completions fire on the transport's execution context:

- **epoll (Linux)**: the `Run` thread — the contract is unchanged there.
- **Network.framework (macOS)**: one serial dispatch queue per
  connection (listener events on their own serial queue).

The contract consumers program against, on every platform:

- Per-connection completions are always serialized, in order.
- Completions for different connections may run concurrently —
  cross-connection state in user handlers needs the user's own
  synchronization.
- Connection methods (`SendText`, `Close`, …) are callable from that
  connection's callback context; `Stop` is callable from any thread.

This is the same contract uWebSockets and Netty publish. The session
layer keeps its hot path lock-free by queue confinement; its only lock
guards the connection registry on accept/close (cold path).

## Consequences

- `wsecho`/`wsinterop`-style per-connection handlers work unchanged;
  handlers aggregating across connections must synchronize on macOS.
- The transport adopts foreign GCD threads into the FPC RTL on entry
  (std-file threadvars; thread-safe heap mode from construction) so
  Pascal handlers behave normally there.
- Per-connection queues give the macOS transport multi-core parallelism
  the single-threaded epoll reactor does not have; the Linux equivalent
  (SO_REUSEPORT sharding) stays a measured follow-up.
- An IOCP transport (duetto 0.3.0) fits the same contract with a
  completion-port thread as its context.
