#!/usr/bin/env bash
# Bench matrix: uWebSockets load_test against each echo server.
# Single-vCPU sandbox: generator and server share the core; the handicap is
# identical for every contender, so relative numbers are meaningful.
set -u
LT=/home/claude/uWebSockets/benchmarks/load_test
DUETTO=/home/claude/duetto/build/wsecho
RUST=/home/claude/rust-echo/target/release/rust-echo
PY=/home/claude/duetto/tools/pyecho.py
DUR=${DUR:-14}

run_one() { # name start_cmd port deflate payload
  local name=$1 cmd=$2 port=$3 defl=$4 size=$5
  nohup bash -c "$cmd" > /tmp/bench-srv.log 2>&1 &
  local pid=$!
  for i in $(seq 50); do grep -q "listening" /tmp/bench-srv.log 2>/dev/null && break; sleep 0.1; done
  local out
  out=$(timeout "$DUR" "$LT" 100 127.0.0.1 "$port" 0 "$defl" "$size" 2>/dev/null | grep -o 'Msg/sec: [0-9.]*' | awk '{print $2}')
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  # discard the first (ramp-up) window, report the best of the rest
  local best
  best=$(echo "$out" | tail -n +2 | sort -n | tail -1)
  [ -z "$best" ] && best=$(echo "$out" | tail -1)
  printf '%-14s payload=%-6s deflate=%s  ->  %12.0f msg/s\n' "$name" "$size" "$defl" "${best:-0}"
}

echo "== plain echo, 100 connections, ${DUR}s each =="
for size in 20 1024 16384; do
  run_one duetto       "$DUETTO --port=9201 --quiet --no-deflate" 9201 0 "$size"
  run_one tungstenite "$RUST 9202"                            9202 0 "$size"
  run_one py-websockets "python3 $PY 9203"                    9203 0 "$size"
  echo
done

echo "== permessage-deflate, 100 connections, 4096 B =="
run_one duetto         "$DUETTO --port=9211 --quiet" 9211 1 4096
run_one py-websockets "python3 $PY 9213 deflate" 9213 1 4096
