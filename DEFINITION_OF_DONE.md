# Definition of Done

A change is done only when every applicable requirement below is
satisfied. A requirement may be marked not applicable only with a
recorded reason.

## Implementation

- The delivered behaviour matches its investigated issue or
  user-confirmed mini-spec, including non-goals and failure behaviour.
- The change satisfies the [AGENTS.md](AGENTS.md) hard constraints —
  in particular: protocol rules live in `WS.Protocol` only, and no new
  dependencies arrive without explicit maintainer approval.
- Hot-path deviations from the RTL are justified by a `wsbench`
  measurement per the RTL policy in
  [code-style.md](docs/code-style.md); no hand-rolled crypto.
- The solution is the smallest complete change; no unrelated
  refactoring rides along.
- Terminology matches [CONTEXT.md](CONTEXT.md).

## Tests and verification

- The universal project gate passes:

  ```sh
  lwpt install --frozen
  lwpt format --check
  lwpt build            # Linux; on macOS the platform-appropriate targets
  lwpt test
  ```

- Focused tests covering the changed behaviour pass first, including
  negative paths (violations must close with the right code).
- `./build/wsinterop` passes when client, server, or protocol behaviour
  changed (Linux until the macOS backend lands).
- Protocol-behaviour changes anticipate the Autobahn suite: it runs on
  every push to main in both directions and a red or skipped suite
  blocks release; run `tools/autobahn.sh` locally (Linux + Docker) when
  the change plausibly affects conformance.
- `tools/crosscheck.py` passes when wire-level interop behaviour
  changed.
- No test is silently skipped, disabled, or weakened to obtain a pass.
- Benchmark numbers inform the PR description where relevant but never
  become CI assertions.

## Documentation and decisions

- Documentation describes shipped behaviour only; planned behaviour
  stays in issues (current truth beats aspiration).
- Durable architecture decisions made (or reversed) by this change are
  recorded as ADRs under [docs/adr/](docs/adr/) in the implementation
  PR; existing ADRs stay immutable except link maintenance.
- [comparison.md](docs/comparison.md) claims affected by the change are
  re-verified or re-measured, never left stale.

## Review and handoff

- The diff has been self-reviewed against the issue or mini-spec,
  criterion by criterion.
- The pull request is opened ready-for-review (not draft) so external
  review actually runs, and **the external review (CodeRabbit) has
  completed and been triaged before merge** — a review skipped on a
  draft does not count.
- Required CI checks pass before the squash-merge; deferred follow-up
  work is explicit, not hidden.
- The PR body reports the validation commands run and their results.

## Release readiness

- [ci.yml](.github/workflows/ci.yml) is green on the release commit —
  the full platform matrix and the Autobahn suite in both directions.
- The release goes through `/create-release`: changelog lands before
  the tag, the tag is unprefixed SemVer matching `version` in
  `lwpt.toml` (see [deployment.md](docs/deployment.md)).
