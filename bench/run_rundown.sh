#!/usr/bin/env bash
# Run the patchbay relay_degrade_rundown ladder N times and aggregate.
#
# Builds the test binary once (release), runs the full framing x condition x
# direction ladder N times WITHOUT recompiling between runs, concatenates every
# RUNDOWN row into one raw CSV, then reduces it to a combined CSV with
# avg/min/max/stddev per cell and renders a graph from the averages.
#
# The rundown is linux-only, needs unprivileged user namespaces (patchbay runs
# rootless, no sudo), and runs serially. See relay_degrade.rs for the topology.
#
# usage: bench/run_rundown.sh [RUNS]     # RUNS defaults to 3
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$BENCH_DIR/.." && pwd)"
RUNS="${1:-3}"

RAW="$BENCH_DIR/results-raw.csv"
AGG="$BENCH_DIR/results-agg.csv"
PNG="$BENCH_DIR/rundown.png"

TEST_ARGS=(--release -p iroh --test patchbay --features test-utils)

cd "$REPO_DIR"

echo "building test binary (release)..." >&2
cargo test "${TEST_ARGS[@]}" --no-run >&2

# Locate the compiled patchbay test binary without depending on jq.
BIN="$(cargo test "${TEST_ARGS[@]}" --no-run --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*deps/patchbay-[^"]*"' \
  | head -1 | sed 's/.*:"//; s/"$//')"
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "could not locate patchbay test binary" >&2
  exit 1
fi
echo "using $BIN" >&2

: > "$RAW"
for i in $(seq 1 "$RUNS"); do
  echo "=== run $i/$RUNS ===" >&2
  # The binary self-initialises user namespaces; capture only RUNDOWN rows.
  "$BIN" relay_degrade_rundown --ignored --test-threads=1 --nocapture 2>/dev/null \
    | grep '^RUNDOWN,' | tee -a "$RAW" | sed "s/^/[run $i] /" >&2
done

echo "aggregating $(grep -c '^RUNDOWN,' "$RAW") rows over $RUNS run(s)..." >&2
python3 "$BENCH_DIR/plot_rundown.py" "$RAW" --csv "$AGG" -o "$PNG"

echo >&2
echo "raw:   $RAW" >&2
echo "agg:   $AGG" >&2
echo "graph: $PNG" >&2
