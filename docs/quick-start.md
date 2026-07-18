# Quick start

## Executive Summary

- Prerequisites: FPC 3.2.2, the lwpt **release binary** on PATH, Lefthook, and Docker for the Autobahn suite.
- `lwpt install` resolves dependencies from the lwpt release tag, `lwpt build` compiles the programs, `lwpt test` runs the unit suites.
- `WS.Server` (and therefore `wsecho`, `wsinterop`, `wsbench`) is Linux-only; on macOS build `wsprobe` and `wsautobahn`.
- `lefthook install` wires the pre-commit formatter hook.

## Setup

Install lwpt from its release (pick the tarball for your platform —
`linux-x64`, `linux-arm64`, `macos-arm64`, `macos-x64`):

```bash
curl -fsSLO https://github.com/frostney/lwpt/releases/download/0.2.0/lwpt-0.2.0-macos-arm64.tar.gz
curl -fsSLO https://github.com/frostney/lwpt/releases/download/0.2.0/lwpt-0.2.0-checksums.txt
shasum -a 256 -c <(grep macos-arm64 lwpt-0.2.0-checksums.txt)
tar xzf lwpt-0.2.0-macos-arm64.tar.gz
export PATH="$PWD/lwpt-0.2.0-macos-arm64:$PATH"   # or copy lwpt into ~/bin
```

Then set up the project:

```bash
git clone https://github.com/frostney/duetto.git && cd duetto
lwpt install        # resolve deps from the lwpt release tag, write lwpt.cfg
lefthook install    # pre-commit formatter hook
```

The `httpclient`, `testing`, and `cli` dependencies resolve from the
`frostney/lwpt` 0.2.0 release tag with include filters (see `lwpt.toml`);
no sibling checkout is needed. The committed `.lwpt/modules/` tree plus
`lwpt.lock` make `lwpt install --frozen` work offline (CI mode).

## Build and test

```bash
lwpt build                      # all five programs (Linux)
lwpt build wsprobe wsautobahn   # client-side programs on macOS
lwpt test                       # five suites, all green
./build/wsinterop               # live-socket battery, exit 0 = pass
```

## Run something

```bash
./build/wsecho --port=9001                  # echo server (Linux)
./build/wsprobe ws://localhost:9001/ --deflate   # probe it from a second shell
```

For the full command set (formatter, Autobahn, benchmarks) see
[tooling.md](tooling.md).
