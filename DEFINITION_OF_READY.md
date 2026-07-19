# Definition of Ready

Use this gate before implementing an issue, idea, refactor, or
documentation change in duetto. A requirement may be marked not
applicable only with a recorded reason.

## Ready to investigate

- The desired outcome, current behaviour, affected surface, and
  non-goals are stated clearly enough to verify later.
- The work has been checked against [VISION.md](VISION.md). Any
  conflict with the performance-on-conformance direction or the
  not-goals fence is explicit and accepted before implementation.
- The root [AGENTS.md](AGENTS.md) hard constraints have been read.
- Applicable project skills under `.agents/skills/` have been
  identified before planning.
- The relevant docs have been identified before forming a plan:
  [Architecture](docs/architecture.md), [Code style](docs/code-style.md),
  [Tooling](docs/tooling.md), [CONTEXT.md](CONTEXT.md), and the ADRs
  under [docs/adr/](docs/adr/).

## Ready to plan

- The relevant code path has been traced in source; documentation or
  memory alone is not treated as proof.
- The owning layer is identified and respects the layering: protocol
  behaviour belongs in `WS.Protocol` only — if the plan puts an
  RFC 6455/7692 rule anywhere else, the plan is wrong.
- Claimed RFC 6455/7692 behaviour has been checked against the RFC
  text, not remembered.
- Platform impact is explicit: which backends, which CI legs, and
  whether the change touches the completion seam
  ([ADR-0001](docs/adr/0001-completion-shaped-backend-seam.md)).
- Any hot-path plan that bypasses the RTL cites the `wsbench`
  measurement that justifies it (RTL policy in
  [code-style.md](docs/code-style.md)).
- The testing strategy is identified: co-located unit suites, the
  `wsinterop` battery, Autobahn implications, and
  `tools/crosscheck.py` where interop behaviour changes.
- The important design questions have been grilled one decision at a
  time, and the chosen behaviour is recorded. If implementation will
  make or reverse an architectural decision, the issue or mini-spec
  says the implementation PR requires an ADR.

## Ready to edit

- Work starts from freshly fetched remote `main` on a focused feature
  branch, following the project `git-workflow` skill (merge, never
  rebase).
- Generated-file ownership is known: `lwpt.cfg`, `lwpt.lock`, and
  `.lwpt/` state come from `lwpt install`; `build/` and
  `tests/autobahn/reports/` are never committed.
- The validation commands needed for completion are known before
  editing (see [DEFINITION_OF_DONE.md](DEFINITION_OF_DONE.md)).
- Existing local changes have been inspected and will not be
  overwritten.
