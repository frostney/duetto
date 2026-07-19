# ADR 0001 — Completion-shaped backend seam in WS.Server

Date: 2026-07-19
Status: accepted

## Context

`WS.Server` is a single-threaded epoll reactor, Linux-only. duetto is
going cross-platform (macOS, Windows), and the maintainer decided the
Windows backend goes straight to IOCP — no readiness-based first cut —
while the macOS backend uses Network.framework's C API. Both of those
APIs are completion-based (submit an operation, get called back when it
finishes), while epoll and kqueue are readiness-based (get told a fd is
ready, then perform the operation).

A readiness-shaped abstraction cannot host a completion-based backend:
there is no "tell me when I could write" moment to surface. The reverse
composes — a readiness loop can implement submit/complete semantics by
performing the operation when the fd signals ready.

## Decision

The backend seam extracted from `WS.Server` is completion-shaped:
backends accept submitted receive/send/accept/close operations and
report completions. The epoll backend implements this contract over its
readiness loop; IOCP and Network.framework implement it natively.

## Consequences

- The seam is designed once and survives all three planned backends;
  the Windows/IOCP release (duetto 0.3.0) does not start by redoing
  the seam shipped for macOS (duetto 0.2.0).
- The epoll backend carries a small adapter layer (readiness →
  completion). Its hot path must stay allocation-free; the RTL policy
  in [code-style.md](../code-style.md) governs how such hot-path code
  is written and justified.
- Protocol behaviour stays in `WS.Protocol` (sans-I/O); the seam moves
  bytes and lifecycle events only.
