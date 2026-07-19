# Context

Domain language for duetto. Terms here are canonical; code, docs, and
issues use them in exactly this sense.

## Glossary

- **Sans-I/O core** — the protocol state machine (`WS.Protocol` and the
  units under it) that consumes and produces bytes without performing
  any I/O. `WS.Protocol` owns all RFC 6455 rules; `WS.Deflate`
  implements RFC 7692 beneath it.
- **Backend** — a platform I/O provider behind the completion seam
  (ADR-0001): it moves bytes and connection lifecycle events between
  the OS and the sans-I/O core. Existing: epoll (Linux, inside
  `WS.Server`, adapter to the seam pending); planned:
  Network.framework (macOS), IOCP (Windows).
- **Completion model** — the seam's contract: operations are submitted
  and later reported complete. Readiness-based OS APIs (epoll) adapt to
  it; completion-based APIs (IOCP, Network.framework) implement it
  natively.
- **Hot path** — code on the per-message byte-moving route (masking,
  UTF-8 validation, frame parse, backend I/O). Subject to the RTL
  policy in [docs/code-style.md](docs/code-style.md).
