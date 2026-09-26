#!/usr/bin/env bash
# Local Windows check without Windows: cross-compile a duetto program
# for i386-win32 and run it under Wine, both in Docker (OrbStack or
# Docker Desktop). win32 is one of the two Windows CI targets and drives
# the same IOCP transport as win64, so this is the fast pre-push loop
# for anything touching WS.Transport.Iocp — not a substitute for the CI
# legs (real kernel, SChannel, win64).
#
#   tools/win32-wine.sh                 # build images if missing, run wsinterop
#   DUETTO_WIN32_PUBLISH=9001 tools/win32-wine.sh wsecho --port=9001
#                                       # publish the port on 127.0.0.1
#   DUETTO_WIN32_REBUILD=1 tools/win32-wine.sh   # force image rebuild
#
# Images: duetto-win32-cross:3.2.2 (FPC cross toolchain built from the
# checksum-verified source tarball, ~2 min on first build) and
# duetto-wine32:bookworm (Wine 8, i386 Debian).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROGRAM=${1:-wsinterop}; shift || true
OUT=${DUETTO_WIN32_OUT:-"${ROOT}/build/win32-wine"}
# Docker bind mounts need an absolute path (a bare name would silently
# become a named volume).
mkdir -p "${OUT}" && OUT="$(cd "${OUT}" && pwd)"
PUBLISH=${DUETTO_WIN32_PUBLISH:-}
CROSS_IMAGE=duetto-win32-cross:3.2.2
WINE_IMAGE=duetto-wine32:bookworm

need_image() {
  local image=$1 dockerfile=$2 platform=${3:-}
  if [ "${DUETTO_WIN32_REBUILD:-}" = "1" ] || ! docker image inspect "${image}" >/dev/null 2>&1; then
    echo "== building ${image}"
    docker build ${platform:+--platform "${platform}"} -f "${ROOT}/tools/win32/${dockerfile}" -t "${image}" "${ROOT}/tools/win32"
  fi
}

need_image "${CROSS_IMAGE}" Dockerfile.cross
need_image "${WINE_IMAGE}" Dockerfile.wine linux/386

echo "== cross-compiling ${PROGRAM} for i386-win32"
# A failed compile must not fall through to a previous run's .exe: clear
# it first, and fail on the compiler's status (grep's own "no match" is
# fine). --user keeps the outputs owned by the caller on rootful Docker.
rm -f "${OUT}/${PROGRAM}.exe"
docker run --rm --user "$(id -u):$(id -g)" -v "${ROOT}:/workspace:ro" -v "${OUT}:/out" \
  "${CROSS_IMAGE}" "${PROGRAM}" \
  | grep -E "Error|Fatal|Warning|lines compiled" || [ "${PIPESTATUS[0]}" -eq 0 ]
[ -f "${OUT}/${PROGRAM}.exe" ] || { echo "error: ${OUT}/${PROGRAM}.exe was not produced" >&2; exit 1; }

echo "== running ${PROGRAM}.exe under Wine"
# --init: Wine re-parents its service processes to PID 1, and a shell
# there would wait on them forever; tini reaps them instead.
docker run --rm --init --platform linux/386 \
  ${PUBLISH:+-p "127.0.0.1:${PUBLISH}:${PUBLISH}"} \
  -v "${OUT}:/artifacts:ro" "${WINE_IMAGE}" "${PROGRAM}.exe" "$@"
