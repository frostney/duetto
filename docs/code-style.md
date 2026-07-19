# Code style

## Executive Summary

- Delphi mode, `{$H+}`, and all project-wide directives live in `source/units/Shared.inc` — every unit pulls `{$I Shared.inc}`, directives are never repeated per file.
- Naming follows the native-nostalgia-stack conventions: `T`/`I`/`E` type prefixes, `F` fields, `A` parameters, PascalCase everywhere, no abbreviations beyond standard acronyms.
- `lwpt format` is the canonical formatter; `--check` is the CI / pre-commit form.
- Units are namespaced in the filename (`WS.<Name>.pas`) and flat under `source/units/`; tests are co-located as `WS.<Name>.Test.pas`.
- The library's public surface is deliberately minimal; protocol rules belong in `WS.Protocol` only.

## Compiler directives

`source/units/Shared.inc` holds the single source of truth: Delphi mode,
`{$H+}`, `{$M+}`, `advancedrecords`, and the dev/production check matrix
(range/overflow/stack/object checks on in dev, off under `-dPRODUCTION`).
Changing a project-wide flag means editing the include, not every file.

## Naming

- Classes `T<Name>`, interfaces `I<Name>`, exceptions `E<Name>`.
- Private fields use the `F` prefix; parameters of two or more letters use
  the `A` prefix.
- Functions, procedures, methods, locals, and constants use `PascalCase` —
  no underscores, no numeric suffixes.
- No abbreviations; industry-standard acronyms (`UTF8`, `TLS`, `RSV`,
  `TCP`) keep their usual casing.

## Layout and API surface

- One unit per concern, namespaced filename `WS.<Name>.pas`, flat under
  `source/units/`.
- `interface` declares only the public API; heavy or cycle-causing
  dependencies go in the `implementation uses` clause.
- `const` parameters by default; `var`/`out` only when mutated.
- No magic literals — extract named constants, in `interface` when shared.
- Performance-sensitive small routines are marked `inline`.

## RTL policy

duetto aims to rival C and Rust implementations; on hot paths, prefer
direct OS APIs (syscalls, WinSock2, epoll/IOCP/Network.framework) and
hand-rolled primitives over RTL/FCL conveniences whenever measurement
shows the RTL costs — the inlined base64 and stack-buffer handshake builders (see
`docs/comparison.md`) set the precedent. RTL use is fine off the hot
path; replacing it is justified by a `wsbench` number, not by taste.

## Formatter

`lwpt format` rewrites sources in place (uses-clause grouping, identifier
casing); `lwpt format --check` exits non-zero on drift and is what CI and
the Lefthook pre-commit hook run. Style rules are encoded in the tool —
adding a rule means changing lwpt's formatter, not adding a config file
here.
