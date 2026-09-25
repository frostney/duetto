#!/usr/bin/env bash
# Bench matrix: uWebSockets load_test against each echo server, plus a
# permessage-deflate pass driven by tools/deflbench.py.
#
#   tools/benchmatrix.sh
#
# Every path is overridable; a contender whose binary is missing is
# reported as skipped, and a run that produced no samples says so rather
# than scoring 0:
#
#   LOAD_TEST   uWebSockets benchmarks/load_test  (default: load_test on PATH)
#   DUETTO      duetto echo server                (default: build/wsecho)
#   RUST_ECHO   tungstenite echo (tools/rust-echo) (default: its release build)
#   PYTHON      interpreter with `websockets`     (default: python3; the
#               deflate pass needs websockets >= 14)
#   DUR         seconds per plain-echo run         (default: 14). load_test
#               reports one Msg/sec sample every 4 s and the first covers
#               the ramp-up, so the score is the best full 4 s window
#               after it: 14 s gives two, anything under 12 s fewer.
#   SIZES       plain-echo payload sizes          (default: 20 1024 16384 262144)
#   SERVER_CPU / CLIENT_CPU
#               pin server / generator with taskset (Linux). Unset = no
#               pinning. Same value for both = the shared-core setup;
#               different physical cores = the generator stops competing
#               with the server.
#
# Build duetto in release mode first (`lwpt build --mode release`): a dev
# build keeps range and overflow checks on. Needs GNU stdbuf and timeout
# (coreutils; gstdbuf / gtimeout on macOS): load_test's per-window
# "Msg/sec" lines are otherwise block-buffered into the pipe and lost when
# timeout kills it.
set -u
export LC_ALL=C # sort -n and printf %f must not follow a decimal-comma locale

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOAD_TEST=${LOAD_TEST:-load_test}
DUETTO=${DUETTO:-$ROOT/build/wsecho}
RUST_ECHO=${RUST_ECHO:-$ROOT/tools/rust-echo/target/release/rust-echo}
PYTHON=${PYTHON:-python3}
DUR=${DUR:-14}
SIZES=${SIZES:-20 1024 16384 262144}
SERVER_CPU=${SERVER_CPU:-}
CLIENT_CPU=${CLIENT_CPU:-}
DEFLATE_CONNS=50
DEFLATE_SECS=8

SRV_LOG=$(mktemp)
GEN_LOG=$(mktemp)
SRV_PID=
GEN_PID=
# Background jobs of a non-interactive shell ignore SIGINT, so an
# interrupted run must stop its server and generator itself or leave them
# holding a port. Both run in the background and are waited for: a
# trapped signal interrupts `wait` at once, where a foreground child
# that exits normally after SIGINT would let the script carry on.
cleanup() {
  [ -n "$GEN_PID" ] && kill "$GEN_PID" 2>/dev/null
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
  # Reap them, so a re-run right after an interrupt finds the ports free.
  [ -n "$GEN_PID" ] && wait "$GEN_PID" 2>/dev/null
  [ -n "$SRV_PID" ] && wait "$SRV_PID" 2>/dev/null
  rm -f "$SRV_LOG" "$GEN_LOG"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

STDBUF=$(command -v stdbuf || command -v gstdbuf || true)
TIMEOUT=$(command -v timeout || command -v gtimeout || true)
if [ -z "$STDBUF" ] || [ -z "$TIMEOUT" ]; then
  echo "error: GNU stdbuf and timeout are required (coreutils; gstdbuf/gtimeout on macOS)" >&2
  exit 1
fi
if [ "$DUR" -lt 12 ]; then
  echo "warning: DUR=$DUR leaves fewer than two full 4 s windows after the ramp-up" >&2
fi
if ! command -v "$LOAD_TEST" >/dev/null 2>&1; then
  echo "error: load_test not found (set LOAD_TEST to uWebSockets' benchmarks/load_test)" >&2
  exit 1
fi

# Command prefixes, not functions: timeout and `&` need a real program.
# ${A[@]+"${A[@]}"} expands an empty array safely under set -u on bash < 4.4.
SRV_PIN=()
GEN_PIN=()
[ -n "$SERVER_CPU" ] && SRV_PIN=(taskset -c "$SERVER_CPU")
[ -n "$CLIENT_CPU" ] && GEN_PIN=(taskset -c "$CLIENT_CPU")

python_websockets_major() { # prints the major version, or nothing
  "$PYTHON" -c 'import websockets; print(websockets.__version__.split(".")[0])' 2>/dev/null
}

run_generator() { # command... ; stdout to $GEN_LOG, waited for interruptibly
  "$@" > "$GEN_LOG" &
  GEN_PID=$!
  wait "$GEN_PID"
  local rc=$?
  GEN_PID=
  return $rc
}

PORT=9200
next_port() { PORT=$((PORT + 1)); }

start_server() { # command... ; sets SRV_PID; fails if it never listens
  : > "$SRV_LOG"
  ${SRV_PIN[@]+"${SRV_PIN[@]}"} "$@" > "$SRV_LOG" 2>&1 &
  SRV_PID=$!
  for _ in $(seq 100); do
    grep -qi "listening" "$SRV_LOG" 2>/dev/null && return 0
    kill -0 "$SRV_PID" 2>/dev/null || break
    sleep 0.1
  done
  # The last error-looking line names the cause for both an FPC
  # backtrace ("Exception: bind ... failed") and a Python traceback.
  echo "  server did not come up: $* ($(grep -i -E 'error|exception|failed' "$SRV_LOG" | tail -1))" >&2
  stop_server
  return 1
}

stop_server() {
  kill "$SRV_PID" 2>/dev/null
  wait "$SRV_PID" 2>/dev/null
  SRV_PID=
}

run_one() { # name size command... (call next_port first; the command uses $PORT)
  local name=$1 size=$2
  shift 2
  if ! start_server "$@"; then
    printf '%-14s payload=%-7s ->  server failed to start\n' "$name" "$size"
    return
  fi
  local out best
  local rc=0
  run_generator "$TIMEOUT" "$DUR" ${GEN_PIN[@]+"${GEN_PIN[@]}"} "$STDBUF" -oL \
    "$LOAD_TEST" 100 127.0.0.1 "$PORT" 0 0 "$size" || rc=$?
  stop_server
  # The run is meant to end by timeout (124). Anything else means the
  # generator stopped early, and its samples are not a full run.
  if [ "$rc" -ne 124 ] && [ "$rc" -ne 0 ]; then
    printf '%-14s payload=%-7s ->  generator exited early (status %s)\n' "$name" "$size" "$rc"
    return
  fi
  out=$(grep -o 'Msg/sec: [0-9.]*' "$GEN_LOG" | awk '{print $2}')
  if [ -z "$out" ]; then
    printf '%-14s payload=%-7s ->  no samples (generator failed or DUR too short)\n' "$name" "$size"
    return
  fi
  # discard the first (ramp-up) window, report the best of the rest
  best=$(echo "$out" | tail -n +2 | sort -n | tail -1)
  [ -z "$best" ] && best=$(echo "$out" | tail -1)
  printf '%-14s payload=%-7s ->  %10.0f msg/s   windows: %s\n' \
    "$name" "$size" "$best" "$(tr '\n' ' ' <<<"$out")"
}

PY_MAJOR=$(python_websockets_major)

echo "== plain echo, 100 connections, ${DUR}s each," \
  "server cpu ${SERVER_CPU:-any}, generator cpu ${CLIENT_CPU:-any} =="
[ -x "$DUETTO" ] ||
  echo "duetto         skipped ($DUETTO missing — lwpt build --mode release)"
[ -x "$RUST_ECHO" ] ||
  echo "tungstenite    skipped ($RUST_ECHO missing — cargo build --release --locked in tools/rust-echo)"
[ -n "$PY_MAJOR" ] ||
  echo "py-websockets  skipped ($PYTHON has no websockets module)"
for size in $SIZES; do
  if [ -x "$DUETTO" ]; then
    next_port
    run_one duetto "$size" "$DUETTO" --quiet --no-deflate --port="$PORT"
  fi
  if [ -x "$RUST_ECHO" ]; then
    next_port
    run_one tungstenite "$size" "$RUST_ECHO" "$PORT"
  fi
  if [ -n "$PY_MAJOR" ]; then
    next_port
    run_one py-websockets "$size" "$PYTHON" "$ROOT/tools/pyecho.py" "$PORT"
  fi
  echo
done

# load_test's own deflate mode only scores uWS-shaped servers (it expects
# uncompressed replies), so the deflate pass uses a neutral generator:
# the same Python websockets client against every server. tungstenite's
# echo does not negotiate permessage-deflate and sits this pass out.
echo "== permessage-deflate, $DEFLATE_CONNS connections, 4096 B, tools/deflbench.py client =="
if [ -z "$PY_MAJOR" ] || [ "$PY_MAJOR" -lt 14 ]; then
  echo "skipped (deflbench.py needs websockets >= 14; $PYTHON has ${PY_MAJOR:-none})"
  exit 0
fi
deflate_one() { # name command... (call next_port first)
  local name=$1
  shift
  if ! start_server "$@"; then
    printf '%-14s server failed to start\n' "$name"
    return
  fi
  if run_generator "$TIMEOUT" $((DEFLATE_SECS + 30)) ${GEN_PIN[@]+"${GEN_PIN[@]}"} \
    "$PYTHON" "$ROOT/tools/deflbench.py" "ws://127.0.0.1:$PORT/" \
    "$DEFLATE_CONNS" "$DEFLATE_SECS"; then
    printf '%-14s %s\n' "$name" "$(cat "$GEN_LOG")"
  else
    printf '%-14s failed (exit %s)\n' "$name" "$?"
  fi
  stop_server
}
if [ -x "$DUETTO" ]; then
  next_port
  deflate_one duetto "$DUETTO" --quiet --port="$PORT"
else
  echo "duetto         skipped ($DUETTO missing)"
fi
next_port
deflate_one py-websockets "$PYTHON" "$ROOT/tools/pyecho.py" "$PORT" deflate
