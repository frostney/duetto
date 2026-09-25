# ADR 0004 — Optional gather send on the transport seam

Date: 2026-09-25
Status: accepted

## Context

ADR-0001's seam has one send operation: `SubmitSend(P, Len)`, bytes
taken now, `OnSendReady` for the rest. The session layer therefore
framed every server message into the protocol's out queue — a copy of
the caller's whole payload — before offering the queue to the
transport. On the epoll transport that copy was the largest user-space
cost of a large echo: `FPC_MOVE` took 18% of server CPU at 16 KiB and
40% at 256 KiB under `load_test`, most of it this copy and the
assembly copy on the receive side.

A readiness transport writes synchronously: the kernel has taken the
bytes (or refused them) before the call returns, so the caller's buffer
can go to the socket as it is. A completion transport cannot hand the
caller's buffer to the OS: IOCP's `WSASend` and Network.framework's
`nw_connection_send` complete later, so the transport must own the
bytes until then, and both copy on submit for that reason.

## Decision

The seam gains an optional gather send:

- `SupportsGather` — False by default. A transport returns True only
  for connections where it keeps neither pointer past the call.
- `SubmitSendV(P1, L1, P2, L2)` — `SubmitSend`'s contract over two
  buffers. The inherited default is two `SubmitSend` calls that never
  offer the second buffer after a short first, so it is correct on any
  transport, but nothing calls it unless `SupportsGather` is True.
- A tail the transport did not take is queued and then goes through the
  session's normal flush, so every per-flush policy sees it.

Framing stays in `WS.Protocol`: `DirectHeader` builds the frame header
only when a direct send is valid (server role, so unmasked; no
deflate; close not yet sent; nothing already queued, so it cannot
overtake queued bytes), and `DirectSent` queues whatever part of
header + payload the transport did not take. `WS.Server` tries that
path first for payloads of at least 1 KiB; below that the copy is
cheaper than a two-element gather.

Opted in: the epoll transport's plaintext connections (`sendmsg`).
Not opted in: epoll TLS connections (they encrypt into their own
buffers), IOCP, Network.framework.

## Consequences

- No RFC 6455 rule moves: the transport still moves bytes only.
- A large echo on epoll skips the out-queue copy whenever the socket
  can take the frame: +8% at 16 KiB and at 256 KiB under `load_test`
  (separate cores) when this landed, with 20 B and 1 KiB unchanged.
- A transport opts in without session-layer changes. For IOCP and
  Network.framework that would mean gathering header + payload into
  the one copy they already make on submit, instead of copying the
  queue — not done here, because it could not be measured on those
  platforms.
