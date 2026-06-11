# Agent Instructions

## Hard Constraints

- **FreePascal only.** FPC 3.2.2, Delphi mode, flags centralised in
  `source/units/Shared.inc`. Do not introduce another compiled language or
  repeat compiler directives per unit.
- **lwpt is the only toolchain entry point** — install, build, test, format
  all go through it. Do not add another build system (no Make/CMake for
  builds) and do not invoke `fpc` directly except as `fpc @lwpt.cfg`.
- **`lwpt.cfg` and `lwpt.lock` are generated** by `lwpt install`; never
  hand-edit them. `lwpt.toml` is the manifest you edit.
- **The `units` array in `lwpt.toml` deliberately lists the `.lwpt`
  module source dirs** (lwpt 0.1.0 doesn't discover unit subdirs behind
  include-filtered deps — see the manifest comment). Do not "clean up"
  those entries, and keep `[format] exclude = [".lwpt/**"]` so the
  formatter never rewrites fetched modules.
- **Programs parse flags via lwpt's `cli` package** (`CLI.Options`,
  `CLI.Parser`, `CLI.Help`) — no hand-rolled `ParamStr` loops in
  `source/apps/`.
- **Layout is fixed:** library units in `source/units/` (namespaced
  `WS.*.pas`, tests co-located as `WS.*.Test.pas`), program entry points in
  `source/apps/`, one-off automation in `tools/`, E2E corpora in `tests/`.
- **`build/` and `tests/autobahn/reports/` are generated** — never commit
  them.
- **No new dependencies** beyond lwpt's `httpclient` and `testing` packages
  without explicit maintainer approval.
- **`WS.Protocol` owns all RFC 6455 rules.** Protocol behaviour (close
  codes, fragmentation, masking policy, UTF-8 failure) must not leak into
  the client, the server, or the apps.

## Runtime / Commands

lwpt is the **released binary on PATH** (checksum-verified tarball from
lwpt's GitHub releases — see `docs/quick-start.md`); no sibling checkout,
no bootstrap. Dependencies resolve from the same release tag.

```bash
lwpt install         # resolve deps, regenerate lwpt.cfg + lwpt.lock
lwpt install --frozen  # CI mode: verify lockfile + committed modules, no network
lwpt format --check  # formatter gate (no flag = rewrite in place)
lwpt build           # all programs (Linux; on macOS: lwpt build wsprobe wsautobahn)
lwpt test            # five co-located unit suites
./build/wsinterop    # live-socket battery, exit 0 = pass
tools/autobahn.sh server   # Autobahn fuzzingclient vs wsecho (Linux + Docker)
tools/autobahn.sh client   # Autobahn fuzzingserver vs wsautobahn (Docker)
```

## Code Organization

| Path | Role |
| --- | --- |
| `source/units/` | Library: `WS.Frame`, `WS.Utf8`, `WS.Handshake`, `WS.Deflate`, `WS.Protocol` (sans-I/O core), `WS.Client`, `WS.Server` (Linux epoll) |
| `source/apps/` | Programs: `wsecho`, `wsprobe`, `wsinterop`, `wsbench`, `wsautobahn` |
| `tests/autobahn/` | Autobahn testsuite configs (reports/ is generated) |
| `tools/` | Cross-implementation checks, benchmarks, Autobahn runner |
| `docs/` | Architecture, quick-start, tooling, code style, deployment |

Layering is strictly bottom-up — see [docs/architecture.md](docs/architecture.md).
`WS.Server` is Linux-only (epoll); keep it and anything that uses it out of
Darwin/Windows build paths.

## Testing

- `lwpt test` discovers `source/units/*.Test.pas`; tests are co-located with
  the unit they cover and must keep providing regression value.
- `wsinterop` is the in-repo E2E battery (own client ↔ own server over real
  sockets, plus raw-socket protocol violations).
- The Autobahn suite is the external conformance net (`tools/autobahn.sh`,
  judged by `tools/autobahn-check.py`); CI runs it on every push to main.
- `tools/crosscheck.py` validates against the Python `websockets` reference
  implementation in both directions.
- Nothing in the test stack touches the external network; everything runs
  against local sockets (Docker for the Autobahn container).

## Safety / Boundaries

- Never commit generated state: `build/`, `tests/autobahn/reports/`,
  `.lwpt/tmp/`, `.lwpt/install.lock`.
- Benchmarks (`wsbench`, `tools/benchmatrix.sh`) are measurement tools;
  never wire their numbers into CI assertions.
- Edit `AGENTS.md` only — `CLAUDE.md` is a symlink to it.
