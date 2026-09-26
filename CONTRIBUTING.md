# Contributing to duetto

This file is the contract for human contributors. AI assistants follow
[`AGENTS.md`](AGENTS.md), which carries the same hard constraints;
nothing lives in both files — each links to the other.

## Before you start

- Read the Hard Constraints in [`AGENTS.md`](AGENTS.md): FreePascal 3.2.2
  only, lwpt as the sole toolchain entry point, the fixed layout, no new
  dependencies without maintainer approval, every RFC 6455 rule in
  `WS.Protocol`, and hot paths that avoid the RTL.
- Skim [`docs/architecture.md`](docs/architecture.md) and the ADRs in
  [`docs/adr/`](docs/adr/); a change that challenges one of them is a
  conversation before it is code.
- [`VISION.md`](VISION.md) says what duetto is not. Rooms, pub/sub,
  routing, HTTP/2 transport and legacy drafts are out.

## Setup

[`docs/quick-start.md`](docs/quick-start.md) is the walkthrough. Short
version: FPC 3.2.2 on PATH, the lwpt release binary on PATH, then

```sh
lwpt install --frozen
lwpt build
lwpt test
./build/wsinterop
```

Install the pre-commit hook once with `lefthook install`; it runs the
formatter and regenerates the `AGENTS.md` command block.

## Pull request gate

[`DEFINITION_OF_DONE.md`](DEFINITION_OF_DONE.md) is the checklist. A pull
request is mergeable when:

1. The universal gate is green in CI on Linux, macOS and Windows:
   `install --frozen`, `format --check`, `agents --check`, `health`,
   `duplication`, `build`, `test`, `wsinterop`. PR CI runs `wsinterop`
   on every platform; locally the Definition of Done requires it when
   client, server or protocol behaviour changes.
2. Protocol-behaviour changes keep the Autobahn suite green in both
   directions (it runs on every push to `main`; run `tools/autobahn.sh`
   locally when conformance is plausibly affected).
3. New behaviour has a test that fails without it — a co-located unit
   suite for `WS.*` units, a `wsinterop` case for anything that needs a
   socket.
4. Documentation naming the changed surface is updated in its one
   canonical place, and [`docs/comparison.md`](docs/comparison.md) is
   never left claiming numbers the change invalidated.
5. The review is complete before the merge: a draft is marked ready only
   when CI is green, and the merge waits for the automated review to
   finish.

Pull requests are squash-merged; branches are merged forward, never
rebased.

## Commit messages

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`perf:`, `build:`, `ci:`, `chore:`, `revert:`), imperative mood, no
trailing period. The changelog is generated from them by git-cliff
through `cliff.toml`, so the subject line is what users will read.

## When to write an ADR

Add one under [`docs/adr/`](docs/adr/) when the decision is hard to
reverse, surprising without context, and the result of a real trade-off.
Most changes are none of these.

## Security

Suspected vulnerabilities go through [`SECURITY.md`](SECURITY.md), not
the issue tracker.
