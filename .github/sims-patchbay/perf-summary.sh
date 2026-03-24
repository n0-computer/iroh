#!/usr/bin/env bash
# Generate a perf summary table from patchbay combined-results.json.
# Output format matches the old chuck netsim report table.
#
# Usage: perf-summary.sh [results-dir]
#   results-dir defaults to .patchbay-work/latest

set -euo pipefail

RESULTS_DIR="${1:-.patchbay-work/latest}"
COMBINED="$RESULTS_DIR/combined-results.json"

if [[ ! -f "$COMBINED" ]]; then
  echo "No combined-results.json found in $RESULTS_DIR"
  exit 0
fi

python3 - "$COMBINED" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

rows = []
for run_entry in data.get("runs", []):
    sim = run_entry["sim"]
    for step in run_entry.get("steps", []):
        down_bytes = int(step.get("down_bytes") or 0)
        duration_us = int(step.get("duration") or 0)
        if duration_us == 0:
            continue
        elapsed_s = duration_us / 1_000_000
        mb_s = (down_bytes / 1_000_000) / elapsed_s if elapsed_s > 0 else 0
        gbps = (down_bytes * 8 / 1_000_000_000) / elapsed_s if elapsed_s > 0 else 0
        rows.append({
            "sim": sim,
            "id": step.get("id", ""),
            "down_bytes": down_bytes,
            "elapsed_s": elapsed_s,
            "mb_s": mb_s,
            "gbps": gbps,
        })

if not rows:
    print("No perf results found.")
    sys.exit(0)

# Summary table
print("## Perf Summary\n")
print("| test | throughput (Gbps) | throughput (MB/s) | size (MB) | time (s) |")
print("| ---- | ----------------: | ----------------: | --------: | -------: |")
for r in sorted(rows, key=lambda r: r["sim"]):
    size_mb = r["down_bytes"] / 1_000_000
    print(f"| {r['sim']} | {r['gbps']:.2f} | {r['mb_s']:.2f} | {size_mb:.0f} | {r['elapsed_s']:.2f} |")
PYEOF
