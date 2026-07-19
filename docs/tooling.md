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

- **`.github/workflows/pr.yml`** — every PR: the full battery
  (`install --frozen` → `build` → `test` → `wsinterop`) on Linux, macOS,
  and win64 runners plus format-check and a blocking markdownlint job.
  The authoritative pre-merge gate; i386-win32 stays post-merge. The
  Windows legs install online (`lwpt install`, not `--frozen`) until
  lwpt#78 makes the frozen verifier's tree hash path-portable.
- **`.github/workflows/ci.yml`** — push to main: native test matrix
  (x86_64/aarch64 Linux and macOS, x86_64/i386 Windows) plus the full
  Autobahn suite with report artifacts. Every leg builds the full program set and runs the
  unit suites; all legs except x86_64 macOS also run wsinterop and
  `tools/crosscheck.py` against the python `websockets` reference. On
  arm64 macOS the `autobahn-macos` job additionally runs the full
  fuzzingclient battery natively (Intel python-2.7 under Rosetta — the
  Autobahn container needs Docker, which GitHub's macOS runners lack),
  giving the Network.framework transport the same Autobahn net as
  epoll; the client direction stays on the Linux job. The x86_64 macOS
  leg skips the loopback batteries entirely: GitHub's Intel VMs deliver
  Network.framework loopback traffic on a ~60 s timer (duetto#11).

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

## CI experimentation (spike pattern)

For anything that can only be validated in the runner environment
(toolchain provisioning, OS-specific behaviour, runner quirks), use a
**spike branch** instead of iterating on a real PR:

1. Branch `spike/<topic>` off main; commit a dedicated workflow with
   `on: push: branches: [spike/**]` so every push self-triggers — and a
   header banner marking it **never-merge**.
2. Iterate on the real runner; keep each push a single hypothesis.
3. Record the verdict and evidence (run links, key log lines) on the
   driving issue — the spike's output is knowledge, not code.
4. Graduate a validated recipe via a clean PR from main; **delete the
   spike branch with the verdict** (the workflow stays armed until the
   branch dies).

Proven by the native-Autobahn spike (issue #10, run 29694505585:
recipe validated in five pushes, graduated as the `autobahn-macos`
job).

## Markdown

markdownlint-cli2 (config: `.markdownlint-cli2.jsonc`) lints every
committed Markdown file; the PR `docs` job is blocking.
