# Tooling

## Executive Summary

- FPC **3.2.2** (Delphi mode) is the pinned compiler; the [lwpt](https://github.com/frostney/lwpt) **0.2.0 release binary** is the single toolchain entry point for install / build / test / format.
- The Autobahn testsuite runs via Docker (`crossbario/autobahn-testsuite`) through `tools/autobahn.sh`, judged by `tools/autobahn-check.py`.
- Lefthook runs `lwpt format` pre-commit; markdownlint and the PR workflow are the blocking gates.
- CI: `pr.yml` is the fast Ubuntu pre-merge gate, `ci.yml` (push to main) adds the platform matrix and the Autobahn suite.
- Changelog generation is git-cliff from Conventional Commits (`cliff.toml`).

## Toolchain

| Tool | Version / source | Role |
| --- | --- | --- |
| FPC | 3.2.2 (apt / brew) | compiler, Delphi mode via `source/units/Shared.inc` |
| lwpt | 0.2.0 release binary (checksum-verified tarball, pinned as `LWPT_VERSION` in CI) | build, test discovery, formatter, dependency install |
| Lefthook | ≥ 1.5 | pre-commit formatter hook (`lefthook install`) |
| Docker | any recent | Autobahn testsuite container |
| git-cliff | latest | changelog generation from Conventional Commits |

## Commands

```bash
lwpt install         # resolve deps, regenerate lwpt.cfg + lwpt.lock
lwpt install --frozen  # CI mode: verify lockfile + committed modules, refuse network
lwpt format          # rewrite Pascal sources in place
lwpt format --check  # CI / hook form: exit non-zero on drift
lwpt build [target]  # binaries land under build/
lwpt test            # discovers source/units/*.Test.pas
./build/wsinterop    # live-socket E2E battery
./build/wsbench      # component benchmarks (measurement only — never a CI assertion)
tools/benchmatrix.sh # cross-implementation benchmark matrix
tools/crosscheck.py  # validate against Python websockets, both directions
```

## Autobahn testsuite

Industry conformance fuzzing, run in both directions via
`crossbario/autobahn-testsuite` (Docker):

```bash
tools/autobahn.sh server   # suite fuzzes build/wsecho (Linux only: epoll + host networking)
tools/autobahn.sh client   # suite's fuzzingserver fuzzes build/wsautobahn
```

- Configs live in `tests/autobahn/*.json`; reports land in
  `tests/autobahn/reports/` (gitignored; uploaded as a CI artifact).
- The server direction tests two `wsecho` instances: with deflate
  (agent `duetto`) and without (agent `duetto-nodeflate`).
- The client direction runs `wsautobahn` twice: agent `duetto` and agent
  `duetto-deflate` (permessage-deflate offered).
- `tools/autobahn-check.py` judges `index.json`: `behavior` must be
  OK / NON-STRICT / INFORMATIONAL / UNIMPLEMENTED and `behaviorClose`
  OK / INFORMATIONAL / UNIMPLEMENTED; anything else fails the run.

## CI

- **`.github/workflows/pr.yml`** — every PR: Ubuntu-native lwpt bootstrap,
  `install` → `format --check` → `build` → `test` → `wsinterop`, plus a
  blocking markdownlint job. The authoritative pre-merge gate.
- **`.github/workflows/ci.yml`** — push to main: native test matrix
  (x86_64/aarch64 Linux and macOS, each building the full program set
  and running wsinterop plus `tools/crosscheck.py` against the python
  `websockets` reference) and the full Autobahn suite with report
  artifacts. On the macOS legs the crosscheck is the merge-time
  conformance battery — the Autobahn container needs Docker, which
  GitHub's macOS runners lack.

Both workflows install the lwpt release binary from a checksum-verified
tarball (no sibling checkout, no bootstrap) and verify dependencies
against the committed lockfile via `lwpt install --frozen`; duetto has no
committed toolchain binaries.

### Dependency layout note

The `httpclient` / `testing` / `cli` deps are fetched from the
`frostney/lwpt` release tag with `include = ["packages/<name>/**"]`
filters, which preserve the `packages/<name>/` prefix inside
`.lwpt/modules/<name>/`. lwpt 0.2.0 discovers each dep's units through
its nested manifest, so the project's own `units` array lists only
`source/units`. Dep test files are still excluded at fetch time (they
would otherwise enter `lwpt test` discovery), and `.lwpt/**` is carved
out of the formatter's scope.

## Markdown

markdownlint-cli2 (config: `.markdownlint-cli2.jsonc`) lints every
committed Markdown file; the PR `docs` job is blocking.
