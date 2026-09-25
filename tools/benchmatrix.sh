#!/usr/bin/env bash
# Bench matrix: uWebSockets load_test against each echo server, plus a
# permessage-deflate pass driven by tools/deflbench.py.
#
#   tools/benchmatrix.sh
#
# Every path is overridable; contenders whose binary is missing are
# reported as skipped rather than silently scored 0:
#
#   LOAD_TEST   uWebSockets benchmarks/load_test  (default: load_test on PATH)
#   DUETTO      duetto echo server                (default: build/wsecho)
#   RUST_ECHO   tungstenite echo (tools/rust-echo) (default: its release build)
#   PYTHON      interpreter with `websockets`     (default: python3)
#   DUR         seconds per run                   (default: 14)
#   SIZES       plain-echo payload sizes          (default: 20 1024 16384 262144)
#   SERVER_CPU / CLIENT_CPU
#               pin server / generator with taskset (Linux). Unset = no
#               pinning. Same value for both = the shared-core setup the
#               published numbers used; different physical cores = the
#               generator stops competing with the server.
#
# Build duetto in release mode first (`lwpt build --mode release`): a dev
# build keeps range and overflow checks on. load_test's output is
# line-buffered through stdbuf (GNU coreutils; gstdbuf on macOS) — its
# per-window "Msg/sec" lines are otherwise block-buffered into the pipe
# and lost when timeout kills it, which scores every contender 0.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOAD_TEST=${LOAD_TEST:-load_test}
DUETTO=${DUETTO:-$ROOT/build/wsecho}
RUST_ECHO=${RUST_ECHO:-$ROOT/tools/rust-echo/target/release/rust-echo}
PYTHON=${PYTHON:-python3}
DUR=${DUR:-14}
SIZES=${SIZES:-20 1024 16384 262144}
SERVER_CPU=${SERVER_CPU:-}
CLIENT_CPU=${CLIENT_CPU:-}
SRV_LOG=$(mktemp)
trap 'rm -f "$SRV_LOG"' EXIT

STDBUF=$(command -v stdbuf || command -v gstdbuf || true)
if [ -z "$STDBUF" ]; then
  echo "error: stdbuf (GNU coreutils) is required to read load_test's output" >&2
  exit 1
fi
if ! command -v "$LOAD_TEST" >/dev/null 2>&1; then
  echo "error: load_test not found (set LOAD_TEST to uWebSockets' benchmarks/load_test)" >&2
  exit 1
fi

# Command prefixes (not functions: timeout and `&` need a real program).
SRV_PIN=()
GEN_PIN=()
[ -n "$SERVER_CPU" ] && SRV_PIN=(taskset -c "$SERVER_CPU")
[ -n "$CLIENT_CPU" ] && GEN_PIN=(taskset -c "$CLIENT_CPU")

have_python_websockets() {
  "$PYTHON" -c 'import websockets' >/dev/null 2>&1
}

start_server() { # command... ; sets SRV_PID, waits for "listening"
  : > "$SRV_LOG"
  "${SRV_PIN[@]}" "$@" > "$SRV_LOG" 2>&1 &
  SRV_PID=$!
  for _ in $(seq 100); do
    grep -qi "listening" "$SRV_LOG" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "warning: server did not report listening: $*" >&2
}

stop_server() {
  kill "$SRV_PID" 2>/dev/null
  wait "$SRV_PID" 2>/dev/null
  sleep 0.5 # let the port and the core settle between runs
}

PORT=9200
run_one() { # name size command... (the command is given the port as its last arg)
  local name=$1 size=$2
  shift 2
  PORT=$((PORT + 1))
  start_server "$@" "$PORT"
  local out best
  out=$(timeout "$DUR" "${GEN_PIN[@]}" "$STDBUF" -oL "$LOAD_TEST" 100 127.0.0.1 "$PORT" 0 0 "$size" 2>/dev/null |
    grep -o 'Msg/sec: [0-9.]*' | awk '{print $2}')
  stop_server
  # discard the first (ramp-up) window, report the best of the rest
  best=$(echo "$out" | tail -n +2 | sort -n | tail -1)
  [ -z "$best" ] && best=$(echo "$out" | tail -1)
  printf '%-14s payload=%-7s ->  %10.0f msg/s   windows: %s\n' \
    "$name" "$size" "${best:-0}" "$(echo $out)"
}

# Adapters so every contender takes the port as its final argument.
duetto_plain() { exec "$DUETTO" --quiet --no-deflate --port="$1"; }
duetto_deflate() { exec "$DUETTO" --quiet --port="$1"; }
py_plain() { exec "$PYTHON" "$ROOT/tools/pyecho.py" "$1"; }
py_deflate() { exec "$PYTHON" "$ROOT/tools/pyecho.py" "$1" deflate; }
export -f duetto_plain duetto_deflate py_plain py_deflate
export DUETTO PYTHON ROOT

echo "== plain echo, 100 connections, ${DUR}s each," \
  "server cpu ${SERVER_CPU:-any}, generator cpu ${CLIENT_CPU:-any} =="
for size in $SIZES; do
  if [ -x "$DUETTO" ]; then
    run_one duetto "$size" bash -c 'duetto_plain "$0"'
  else
    echo "duetto         skipped ($DUETTO missing — lwpt build --mode release)"
  fi
  if [ -x "$RUST_ECHO" ]; then
    run_one tungstenite "$size" "$RUST_ECHO"
  else
    echo "tungstenite    skipped ($RUST_ECHO missing — cargo build --release in tools/rust-echo)"
  fi
  if have_python_websockets; then
    run_one py-websockets "$size" bash -c 'py_plain "$0"'
  else
    echo "py-websockets  skipped ($PYTHON has no websockets module)"
  fi
  echo
done

# load_test's own deflate mode only scores uWS-shaped servers (it expects
# uncompressed replies), so the deflate pass uses a neutral generator:
# the same Python websockets client against every server.
echo "== permessage-deflate, 50 connections, 4096 B, tools/deflbench.py client =="
if ! have_python_websockets; then
  echo "skipped ($PYTHON has no websockets module)"
  exit 0
fi
deflate_one() { # name command...
  local name=$1
  shift
  PORT=$((PORT + 1))
  start_server "$@" "$PORT"
  printf '%-14s ' "$name"
  "${GEN_PIN[@]}" "$PYTHON" "$ROOT/tools/deflbench.py" "ws://127.0.0.1:$PORT/" 50 8
  stop_server
}
if [ -x "$DUETTO" ]; then deflate_one duetto bash -c 'duetto_deflate "$0"'; fi
deflate_one py-websockets bash -c 'py_deflate "$0"'
