#!/usr/bin/env bash
# Cross-compile one duetto program for i386-win32.
#   compile-win32 <program-name> [/workspace] [/out]
# The repository is mounted read-only at /workspace; units and the .exe
# land under /out. The project's unit paths come from the committed
# lwpt.cfg (own units + the fetched lwpt packages); the toolchain
# flags mirror lwpt's win32 leg.
set -euo pipefail
program=${1:?program name (wsinterop, wsecho, ...)}
repo=${2:-/workspace}
out=${3:-/out}
prefix=/opt/fpc-cross/lib/fpc/3.2.2
units=${prefix}/units/i386-win32
mkdir -p "${out}/units"
cd "${repo}"
"${prefix}/ppcross386" -Twin32 -Mdelphi -Sh -O2 -dFPC_SOFT_FPUX80 -XPi686-w64-mingw32- -Xm \
  -Fu"${units}/rtl" -Fu"${units}/rtl-objpas" -Fu"${units}/rtl-generics" -Fu"${units}/rtl-extra" \
  -Fu"${units}/fcl-process" -Fu"${units}/paszlib" -Fu"${units}/hash" \
  -Fu/opt/fpc-source/packages/fcl-base/src -Fu/opt/fpc-source/packages/fcl-net/src \
  @lwpt.cfg \
  -FU"${out}/units" -FE"${out}" "source/apps/${program}.pas"
