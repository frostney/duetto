# ADR 0006 — Server opens on Start/Run, not Create

Date: 2026-10-14
Status: accepted.

## Context

`TWSServer.Create` bound the listener and then called `FTransport.Open`.
The host could only assign `OnUpgradeRequest`, `OnOpen`, `OnMessage` and
the other handlers after the constructor returned.

On epoll and IOCP that ordering was harmless, because completions are
dispatched only inside `Run` ([ADR-0003](0003-transport-execution-context.md)),
and a host assigns its handlers before it calls `Run`. On
Network.framework, connections run on GCD queues that do not wait for
`Run`: once `FOpen` is `True`, the listener queue accepts and the
connection queue serves the handshake. A peer that connected between
`Create` and the handler assignments was upgraded with no
`OnUpgradeRequest` veto and no `OnOpen`. The `wsinterop` start section
reproduces it on macOS CI.

## Options

- **(a) Open in `Create`; document "assign handlers quickly".** Keeps
  the API, leaves the race. Rejected.
- **(b) Take the handlers as constructor arguments.** Closes the race,
  but every new handler grows the constructor, and hosts that wire
  handlers after reading `Port` (to template it into a page, for
  example) lose that order.
- **(c) Open on an explicit, idempotent `Start`, which `Run` calls
  first.** Chosen. `Create` still binds and starts the listener, so
  `Port` resolves before `Start` (port 0 included). Existing hosts that
  assign handlers and then call `Run` keep working without changes.

## Decision

`Create` binds, starts the listener and resolves `Port`, but accepts no
connection. `TWSServer.Start` opens the transport. It is idempotent, and
`Run` calls it before the first round. Handlers assigned before `Start`
apply to every connection. Handlers assigned after `Start` race live
connections, as before.

On Network.framework, `Open` issues a `WriteBarrier` before setting
`FOpen`, and `NewConnInvoke` issues a `ReadBarrier` after it reads
`FOpen` as `True`. The handler writes made on the opening thread are
therefore visible to every connection. No other cross-thread state
changes: ADR-0003's execution contexts stand.

## Consequences

- What a peer sees before `Start` depends on the transport. On
  Network.framework the listener is already up, so the TCP connect may
  complete, but the connection is cancelled at once (refused). On epoll
  and IOCP the connection waits in the kernel backlog and is served by
  the hooks in place when `Start` runs.
- `Start` is new public API, so this ships as a minor release (0.7.0).
- Destroying a server that never started is safe and does not block.
