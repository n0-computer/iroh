#!/usr/bin/env bash
# H3 relay throughput benchmark: wss vs wt-unistream vs wt-datagram.
#
# Uses prebuilt binaries in this directory. See README.md for how to build them:
#   iroh-relay-h3      relay, default features (serves WSS and uni-stream WT)
#   iroh-relay-dgram   relay, built with --cfg h3_datagrams (datagram WT)
#   transfer-wss       transfer client without h3-transport (forces WSS)
#   transfer-uni       transfer client, default features + WT-forcing patches
#   transfer-dgram     transfer client, --cfg h3_datagrams + WT-forcing patches
#
# usage: bench/run.sh [RUNS] [DURATION] [MODE]   # MODE = download | upload | bidi
set -u
BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNS="${1:-3}"
DURATION="${2:-10}"
MODE="${3:-bidi}"
PROVIDER_SECRET=0101010101010101010101010101010101010101010101010101010101010101
FETCHER_SECRET=0202020202020202020202020202020202020202020202020202020202020202
LOGDIR="$BENCH_DIR/logs"
mkdir -p "$LOGDIR"

RELAY_PID=""; PROVIDE_PID=""
cleanup() { [ -n "$PROVIDE_PID" ] && kill "$PROVIDE_PID" 2>/dev/null; [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null; PROVIDE_PID=""; RELAY_PID=""; }
trap cleanup EXIT

# run_one <label> <relay_bin> <relay_args> <relay_url> <transfer_bin> <run_idx>
run_one() {
  local label="$1" relay_bin="$2" relay_args="$3" relay_url="$4" transfer="$5" idx="$6"
  local tag="$label-$idx"
  local rlog="$LOGDIR/relay-$tag.log" plog="$LOGDIR/provide-$tag.log" flog="$LOGDIR/fetch-$tag.log"

  RUST_LOG=info "$relay_bin" $relay_args >"$rlog" 2>&1 &
  RELAY_PID=$!
  sleep 2
  IROH_SECRET=$PROVIDER_SECRET RUST_LOG=warn "$transfer" provide \
    --relay-url "$relay_url" --relay-only --insecure --no-pkarr-publish --no-dns-resolve \
    >"$plog" 2>&1 &
  PROVIDE_PID=$!
  sleep 3
  local id
  id=$(grep -oiE "[0-9a-f]{64}" "$plog" | head -1)
  if [ -z "$id" ]; then echo "[$tag] FAILED: no provider id"; head -15 "$plog"; cleanup; return 1; fi

  IROH_SECRET=$FETCHER_SECRET RUST_LOG=warn "$transfer" fetch "$id" \
    --mode "$MODE" --duration "$DURATION" \
    --remote-relay-url "$relay_url" --relay-url "$relay_url" \
    --relay-only --insecure --no-pkarr-publish --no-dns-resolve \
    >"$flog" 2>&1

  # Which transport did the fetcher actually use? (H3 server logs a WT conn.)
  local transport="ws"
  grep -qiE "wt-relay-conn" "$rlog" && transport="wt"
  local up down
  up=$(grep -iE "Uploaded:" "$flog" | grep -oE "[0-9.]+ [KMG]iB/s" | tail -1)
  down=$(grep -iE "Downloaded:" "$flog" | grep -oE "[0-9.]+ [KMG]iB/s" | tail -1)
  printf "  %-14s run %d: transport=%-3s up=%-12s down=%-12s\n" "$label" "$idx" "$transport" "${up:-ERR}" "${down:-ERR}"
  [ -z "$up" ] && { echo "    (fetch tail:)"; tail -6 "$flog" | sed 's/^/    /'; }
  cleanup
  sleep 1
}

echo "=== h3 relay throughput: $RUNS runs, ${DURATION}s, mode=$MODE ==="
for i in $(seq 1 "$RUNS"); do
  run_one "wss"          "$BENCH_DIR/iroh-relay-h3"    "--dev-tls" "https://localhost:8443" "$BENCH_DIR/transfer-wss"   "$i"
  run_one "wt-unistream" "$BENCH_DIR/iroh-relay-h3"    "--dev-tls" "https://localhost:8443" "$BENCH_DIR/transfer-uni"   "$i"
  run_one "wt-datagram"  "$BENCH_DIR/iroh-relay-dgram" "--dev-tls" "https://localhost:8443" "$BENCH_DIR/transfer-dgram" "$i"
done
