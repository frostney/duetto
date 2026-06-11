# Quick start

## Executive Summary

- Prerequisites: FPC 3.2.2, a sibling `../lwpt` checkout (toolchain + dependencies), Lefthook, and Docker for the Autobahn suite.
- `lwpt install` resolves dependencies, `lwpt build` compiles the programs, `lwpt test` runs the unit suites.
- `WS.Server` (and therefore `wsecho`, `wsinterop`, `wsbench`) is Linux-only; on macOS build `wsprobe` and `wsautobahn`.
- `lefthook install` wires the pre-commit formatter hook.

## Setup

```bash
git clone https://github.com/frostney/lwpt.git
git clone https://github.com/frostney/lwws.git
cd lwpt && ./bootstrap.sh && cd ../lwws   # cold-builds ../lwpt/build/lwpt
../lwpt/build/lwpt install                 # resolve deps, write lwpt.cfg
lefthook install                           # pre-commit formatter hook
```

The `lwpt.toml` manifest resolves `httpclient` and `testing` from the
sibling `../lwpt/packages/` checkout — keep the two clones next to each
other.

## Build and test

```bash
../lwpt/build/lwpt build         # all five programs (Linux)
../lwpt/build/lwpt build wsprobe wsautobahn   # the client-side subset (macOS)
../lwpt/build/lwpt test          # five suites, all green
./build/wsinterop                # live-socket battery, exit 0 = pass
```

## Run something

```bash
./build/wsecho --port=9001                  # echo server (Linux)
./build/wsprobe ws://localhost:9001/ --deflate   # probe it from a second shell
```

For the full command set (formatter, Autobahn, benchmarks) see
[tooling.md](tooling.md).
