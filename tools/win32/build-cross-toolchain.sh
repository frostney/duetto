#!/usr/bin/env bash
# Build ppcross386 + the i386-win32 units duetto needs, from the FPC
# source tarball, into /opt/fpc-cross. Runs once, at image build time.
set -euo pipefail

source_archive=${1:?FPC source archive is required}
fpc_version=3.2.2
source_root=/opt/fpc-source
prefix=/opt/fpc-cross
target=i386-win32
compiler=${prefix}/lib/fpc/${fpc_version}/ppcross386

host_arch=$(uname -m)
case "${host_arch}" in
  aarch64) native_pp=ppca64; native_rtl=/usr/lib/aarch64-linux-gnu/fpc/${fpc_version}/units/aarch64-linux/rtl ;;
  x86_64)  native_pp=ppcx64; native_rtl=/usr/lib/x86_64-linux-gnu/fpc/${fpc_version}/units/x86_64-linux/rtl ;;
  *) echo "unsupported build host ${host_arch}" >&2; exit 1 ;;
esac
[ -d "${native_rtl}" ] || native_rtl=$(dirname "$(find /usr/lib -path "*/units/*-linux/rtl/system.ppu" | head -1)")

mkdir -p "${source_root}" "${prefix}/lib/fpc/${fpc_version}" "${prefix}/bin"
tar xzf "${source_archive}" --strip-components=1 -C "${source_root}"

# FPC 3.2.2 assumes an 80-bit native Extended while building the i386
# compiler; hosts without one (aarch64) need bestrealrec to follow suit.
sed -i \
  's/   bestrealrec = TExtended80Rec;/{$ifdef FPC_HAS_TYPE_EXTENDED}\n   bestrealrec = TExtended80Rec;\n{$else}\n   bestrealrec = TDoubleRec;\n{$endif}/' \
  "${source_root}/compiler/i386/cpuinfo.pas"

cd "${source_root}/compiler"
mkdir -p i386/units/${target}
"${native_pp}" -dFPC_SOFT_FPUX80 -di386 -dRELEASE -O2 -Xs -n -Tlinux \
  -Fui386 -Fusystems -Fux86 -Fii386 -Fu"${native_rtl}" \
  -FE. -FUi386/units/${target} pp.pas
mv pp "${compiler}"
chmod +x "${compiler}"

cd "${source_root}"
make rtl PP=/usr/local/bin/ppcross386-wrapper CPU_TARGET=i386 OS_TARGET=win32 \
  OPT=-dFPC_SOFT_FPUX80 BINUTILSPREFIX=i686-w64-mingw32-

units=${prefix}/lib/fpc/${fpc_version}/units/${target}
for d in rtl rtl-objpas rtl-generics rtl-extra fcl-process paszlib hash; do mkdir -p "${units}/${d}"; done
cp rtl/units/${target}/* "${units}/rtl/"

cc() { "${compiler}" -Twin32 -O2 -dFPC_SOFT_FPUX80 -XPi686-w64-mingw32- -Fu"${units}/rtl" "$@"; }

cc -Fu"${units}/rtl-objpas" -FU"${units}/rtl-objpas" \
  -Fipackages/rtl-objpas/src/inc -Fipackages/rtl-objpas/src/win packages/rtl-objpas/src/win/varutils.pp
for u in variants strutils dateutils; do
  cc -Fu"${units}/rtl-objpas" -FU"${units}/rtl-objpas" "packages/rtl-objpas/src/inc/${u}.pp"
done
for u in generics.hashes generics.strings generics.defaults generics.helpers generics.memoryexpanders generics.collections; do
  [ -f "packages/rtl-generics/src/${u}.pas" ] && \
    cc -Fu"${units}/rtl-objpas" -Fu"${units}/rtl-generics" -FU"${units}/rtl-generics" "packages/rtl-generics/src/${u}.pas"
done
cc -FU"${units}/rtl-extra" packages/rtl-extra/src/win/winsock2.pp
cc -Fu"${units}/rtl-extra" -FU"${units}/rtl-extra" \
  -Fipackages/rtl-extra/src/inc -Fipackages/rtl-extra/src/win packages/rtl-extra/src/win/sockets.pp
cc -FU"${units}/fcl-process" -Fipackages/fcl-process/src/win packages/fcl-process/src/pipes.pp
cc -Fu"${units}/fcl-process" -FU"${units}/fcl-process" -Fipackages/fcl-process/src/win packages/fcl-process/src/process.pp
cc -Fu"${units}/hash" -FU"${units}/hash" packages/hash/src/sha1.pp
cc -Fu"${units}/hash" -FU"${units}/hash" packages/hash/src/md5.pp
cc -Fu"${units}/hash" -Fupackages/hash/src -Fu"${units}/paszlib" -FU"${units}/paszlib" packages/paszlib/src/zstream.pp
