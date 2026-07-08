#!/usr/bin/env python3
"""Plot relay_degrade_rundown throughput vs degradation, one line per framing.

Reads the RUNDOWN CSV emitted by the patchbay `relay_degrade_rundown` test
(from stdin or a file arg). Each data row looks like:

    RUNDOWN,<framing>,<degradation>,<direction>,<throughput_kbps>,<ttfb_ms>
    RUNDOWN,<framing>,<degradation>,datagrams,<delivery_pct>,n/a
    RUNDOWN,<framing>,<degradation>,<direction>,FAILED,<reason>

Only bulk rows (direction in download/upload/bidi) with a numeric throughput are
plotted. FAILED and datagram rows are ignored. Output is a PNG with one small
panel per direction; each panel has one line per framing, x = degradation level
(good < moderate < bad), y = throughput (kbit/s).

Run:
    # from a captured log:
    grep RUNDOWN rundown.log | python3 bench/plot_rundown.py -o bench/rundown.png
    # or straight from the test:
    cargo test --release -p iroh --test patchbay relay_degrade_rundown -- \
        --ignored --test-threads=1 --nocapture 2>&1 \
        | grep RUNDOWN | python3 bench/plot_rundown.py -o bench/rundown.png
"""

import argparse
import sys
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

DEG_ORDER = ["good", "moderate", "bad"]
DIRECTIONS = ["download", "upload", "bidi"]
FRAMINGS = ["ws", "wt-uni", "wt-datagram"]


def read_rows(lines):
    # data[direction][framing][degradation] = throughput_kbps
    data = defaultdict(lambda: defaultdict(dict))
    for line in lines:
        line = line.strip()
        if not line.startswith("RUNDOWN,"):
            continue
        parts = line.split(",")
        if len(parts) < 6:
            continue
        _, framing, degradation, direction, metric, _ttfb = parts[:6]
        if direction not in DIRECTIONS:
            continue
        try:
            kbps = float(metric)
        except ValueError:
            continue  # FAILED
        data[direction][framing][degradation] = kbps
    return data


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("infile", nargs="?", help="CSV file (default: stdin)")
    ap.add_argument("-o", "--out", default="rundown.png", help="output PNG path")
    args = ap.parse_args()

    src = open(args.infile) if args.infile else sys.stdin
    data = read_rows(src)
    if args.infile:
        src.close()

    if not data:
        sys.exit("no plottable RUNDOWN rows found on input")

    present = [d for d in DIRECTIONS if d in data]
    fig, axes = plt.subplots(1, len(present), figsize=(5 * len(present), 4.2), squeeze=False)
    x = list(range(len(DEG_ORDER)))

    for ax, direction in zip(axes[0], present):
        for framing in FRAMINGS:
            series = data[direction].get(framing)
            if not series:
                continue
            ys = [series.get(d) for d in DEG_ORDER]
            xs = [xi for xi, y in zip(x, ys) if y is not None]
            yv = [y for y in ys if y is not None]
            if not yv:
                continue
            ax.plot(xs, yv, marker="o", label=framing)
        ax.set_title(direction)
        ax.set_xticks(x)
        ax.set_xticklabels(DEG_ORDER)
        ax.set_xlabel("degradation")
        ax.set_ylabel("throughput (kbit/s)")
        # Throughput spans ~3 orders of magnitude across degradation levels, so a
        # log y-axis keeps the moderate/bad differences legible.
        ax.set_yscale("log")
        ax.grid(True, which="both", alpha=0.3)
        ax.legend()

    fig.suptitle("iroh relay transport throughput vs degradation, by framing")
    fig.tight_layout()
    fig.savefig(args.out, dpi=120)
    print(f"wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
