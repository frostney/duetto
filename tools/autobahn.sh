#!/usr/bin/env bash
# Run the Autobahn testsuite (crossbario/autobahn-testsuite via Docker)
# against duetto and judge the result with tools/autobahn-check.py.
#
#   tools/autobahn.sh client   # fuzzingserver in Docker tests build/wsautobahn
#   tools/autobahn.sh server   # fuzzingclient in Docker tests build/wsecho
#                              # (Linux only — wsecho is the epoll server,
#                              #  and the container reaches it via host
#                              #  networking)
#
# Reports land under tests/autobahn/reports/ (gitignored). Binaries are
# expected in build/ — run `lwpt build` first.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_DIR="$ROOT/tests/autobahn"
REPORT_DIR="$CONFIG_DIR/reports"
IMAGE="crossbario/autobahn-testsuite"
MODE="${1:-}"

wait_for_port() {
  local port="$1" tries=60
  while ! nc -z 127.0.0.1 "$port" 2>/dev/null; do
    tries=$((tries - 1))
    if [ "$tries" -le 0 ]; then
      echo "error: nothing listening on port $port" >&2
      return 1
    fi
    sleep 1
  done
}

run_client_suite() {
  # Direction 1: the suite is the server, our client (wsautobahn) is the
  # peer under test. Runs everywhere Docker runs.
  [ -x "$ROOT/build/wsautobahn" ] || { echo "error: build/wsautobahn missing (run lwpt build)" >&2; exit 1; }
  mkdir -p "$REPORT_DIR"

  echo "=== autobahn fuzzingserver vs build/wsautobahn ==="
  CONTAINER=$(docker run -d --rm \
    -v "$CONFIG_DIR:/config:ro" -v "$REPORT_DIR:/reports" \
    -p 9001:9001 "$IMAGE" \
    wstest -m fuzzingserver -s /config/fuzzingserver.json)
  trap 'docker stop "$CONTAINER" >/dev/null 2>&1 || true' EXIT
  wait_for_port 9001

  "$ROOT/build/wsautobahn" --agent=duetto
  "$ROOT/build/wsautobahn" --agent=duetto-deflate --deflate

  docker stop "$CONTAINER" >/dev/null
  trap - EXIT
  python3 "$ROOT/tools/autobahn-check.py" "$REPORT_DIR/client/index.json"
}

run_server_suite() {
  # Direction 2: the suite is the client, our server (wsecho) is the peer
  # under test. wsecho is Linux/epoll only, and the container reaches the
  # host's listeners via --network=host, which also only works on Linux.
  if [ "$(uname -s)" != "Linux" ]; then
    echo "error: the server direction needs Linux (epoll server + host networking)" >&2
    exit 1
  fi
  [ -x "$ROOT/build/wsecho" ] || { echo "error: build/wsecho missing (run lwpt build)" >&2; exit 1; }
  mkdir -p "$REPORT_DIR"

  echo "=== autobahn fuzzingclient vs build/wsecho ==="
  "$ROOT/build/wsecho" --port=9002 --quiet &
  ECHO_PID=$!
  "$ROOT/build/wsecho" --port=9003 --quiet --no-deflate &
  ECHO_NODEFLATE_PID=$!
  trap 'kill "$ECHO_PID" "$ECHO_NODEFLATE_PID" 2>/dev/null || true' EXIT
  wait_for_port 9002
  wait_for_port 9003

  docker run --rm --network=host \
    -v "$CONFIG_DIR:/config:ro" -v "$REPORT_DIR:/reports" \
    "$IMAGE" wstest -m fuzzingclient -s /config/fuzzingclient.json

  kill "$ECHO_PID" "$ECHO_NODEFLATE_PID" 2>/dev/null || true
  trap - EXIT
  python3 "$ROOT/tools/autobahn-check.py" "$REPORT_DIR/server/index.json"
}

case "$MODE" in
  client) run_client_suite ;;
  server) run_server_suite ;;
  *)
    echo "usage: tools/autobahn.sh {client|server}" >&2
    exit 2
    ;;
esac
