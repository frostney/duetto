# Security policy

duetto parses bytes from untrusted peers — WebSocket frames, HTTP
upgrade requests, permessage-deflate streams — and terminates `wss://`
through platform TLS stacks. Vulnerabilities are realistic; please report
them through the channel below so they can be fixed and disclosed
responsibly.

## Reporting a vulnerability

**Use GitHub Security Advisories.** Open a private advisory at:

<https://github.com/frostney/duetto/security/advisories/new>

Please **do not** file public issues or pull requests for suspected
vulnerabilities — that publishes the report before a fix exists.

A good report includes:

- duetto version (`lwpt.toml` `[package] version`, or the git tag)
- Host platform and transport (`uname -a` / `systeminfo`, `fpc -iV`;
  epoll, Network.framework or IOCP)
- The bytes, handshake or configuration that trigger the issue — a
  `wsprobe` invocation, a raw-socket recipe, or a captured frame sequence
- Your assessment of the impact (memory corruption, crash of the host
  process, protocol bypass, resource exhaustion, TLS verification loss)

Reports are acknowledged within **7 days**, with a fix-or-decline
decision targeted within **30 days** and disclosure **90 days from
acknowledgement** at the latest, earlier when a fix lands sooner.

## Supported versions

| Version line | Supported |
|---|---|
| Latest minor of the current major (`0.x.y`) | Yes — security fixes go here |
| Older minors | No — upgrade; duetto is pre-1.0 |

## In scope

Anything that affects a host embedding `WS.Client` or `WS.Server`:

- Memory-safety defects reachable from the wire (frame parsing, UTF-8
  validation, handshake parsing, inflate).
- A peer bypassing a documented bound — message cap, pending-output cap,
  handshake or close deadlines, connection cap — or pinning resources
  past them.
- Protocol-rule bypasses that let non-conformant input through as valid
  (`WS.Protocol` owns every RFC 6455 rule).
- TLS behaviour that weakens or disables verification on any platform.
- Transport lifetime defects (use-after-free, double close) a peer can
  trigger.

## Out of scope

- The shipped programs (`wsecho`, `wsprobe`, `wsinterop`, `wsbench`,
  `wsautobahn`) as deployable services — they are test and measurement
  tools, not hardened daemons.
- Pre-1.0 API changes; migrations are deliberate, not security issues.
- Test-only code (`*.Test.pas`, `tools/`).

If you are unsure whether something qualifies, open the advisory anyway.
