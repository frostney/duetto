#!/usr/bin/env bash
# Run one .exe from /artifacts under Wine (headless X for Wine's sake),
# passing any further arguments through. Exit code is the program's.
set -euo pipefail
exe=${1:?exe name under /artifacts}; shift
work=$(mktemp -d /tmp/duetto-wine.XXXXXX)
trap 'rm -rf "${work}"' EXIT
cp "/artifacts/${exe}" "${work}/${exe}"
cd "${work}"
xvfb-run -a wine "./${exe}" "$@"
