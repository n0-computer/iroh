#!/usr/bin/env python3
"""Aggregate relay_degrade_rundown results over N runs and plot them.

Reads the raw RUNDOWN CSV emitted by the patchbay `relay_degrade_rundown` test
(concatenated over one or more runs, from stdin or a file arg). Each data row is:

    RUNDOWN,<framing>,<degradation>,<direction>,<metric>,<setup_ms>
    RUNDOWN,<framing>,<degradation>,datagrams,<delivery_pct>,<setup_ms>
    RUNDOWN,<framing>,<degradation>,<direction>,FAILED,<reason>

For every (framing, degradation, direction) cell it collects the metric and the
connection-setup time across all runs and reduces them to avg / min / max /
stddev (sample stddev; 0 for a single run). FAILED rows are counted but excluded
from the stats. The aggregate is written as a single combined CSV (--csv) and
rendered as a PNG (--out): one panel per bulk direction plus a datagram-delivery
panel, each with one line per framing, x = degradation level, y = avg metric,
with a shaded min..max band.

Run:
    python3 bench/plot_rundown.py results-raw.csv --csv results-agg.csv -o rundown.png
    # or straight from the test (single run):
    cargo test --release -p iroh --test patchbay relay_degrade_rundown -- \
        --ignored --test-threads=1 --nocapture 2>&1 \
        | grep RUNDOWN | python3 bench/plot_rundown.py --csv agg.csv -o rundown.png
"""

import argparse
import statistics
import sys
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

DEG_ORDER = ["wifi", "4g", "3g"]
BULK_DIRECTIONS = ["download", "upload", "bidi"]
PANELS = BULK_DIRECTIONS + ["datagrams"]
FRAMINGS = ["ws", "wt-uni", "wt-datagram"]


def reduce_stats(values):
    """avg / min / max / sample-stddev of a list of floats."""
    avg = statistics.fmean(values)
    return {
        "avg": avg,
        "min": min(values),
        "max": max(values),
        "std": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def read_raw(lines):
    """Collect metric and setup samples per (direction, framing, degradation)."""
    # samples[(direction, framing, degradation)] = ([metric...], [setup...], failures)
    metric = defaultdict(list)
    setup = defaultdict(list)
    failures = defaultdict(int)
    for line in lines:
        line = line.strip()
        if not line.startswith("RUNDOWN,"):
            continue
        parts = line.split(",")
        if len(parts) < 6:
            continue
        _, framing, degradation, direction, metric_s, setup_s = parts[:6]
        if direction not in PANELS or framing not in FRAMINGS:
            continue
        key = (direction, framing, degradation)
        try:
            metric[key].append(float(metric_s))
        except ValueError:
            failures[key] += 1  # FAILED cell
            continue
        try:
            setup[key].append(float(setup_s))
        except ValueError:
            pass
    return metric, setup, failures


def aggregate(metric, setup, failures):
    """Build sorted aggregate rows from the collected samples."""
    rows = []
    keys = set(metric) | set(failures)
    for direction in PANELS:
        for framing in FRAMINGS:
            for degradation in DEG_ORDER:
                key = (direction, framing, degradation)
                if key not in keys:
                    continue
                vals = metric.get(key, [])
                row = {
                    "framing": framing,
                    "degradation": degradation,
                    "direction": direction,
                    "runs": len(vals),
                    "failures": failures.get(key, 0),
                    "metric": reduce_stats(vals) if vals else None,
                    "setup": reduce_stats(setup[key]) if setup.get(key) else None,
                }
                rows.append(row)
    return rows


def write_csv(rows, path):
    cols = (
        "framing,degradation,direction,runs,failures,"
        "metric_avg,metric_min,metric_max,metric_std,"
        "setup_avg_ms,setup_min_ms,setup_max_ms,setup_std_ms"
    )
    with open(path, "w") as f:
        f.write(cols + "\n")
        for r in rows:
            m = r["metric"] or {"avg": "", "min": "", "max": "", "std": ""}
            s = r["setup"] or {"avg": "", "min": "", "max": "", "std": ""}

            def fmt(v):
                return f"{v:.1f}" if isinstance(v, float) else v

            f.write(
                f"{r['framing']},{r['degradation']},{r['direction']},"
                f"{r['runs']},{r['failures']},"
                f"{fmt(m['avg'])},{fmt(m['min'])},{fmt(m['max'])},{fmt(m['std'])},"
                f"{fmt(s['avg'])},{fmt(s['min'])},{fmt(s['max'])},{fmt(s['std'])}\n"
            )
    print(f"wrote {path}", file=sys.stderr)


def plot(rows, path):
    # index[(direction, framing)][degradation] = metric stats
    index = defaultdict(dict)
    for r in rows:
        if r["metric"]:
            index[(r["direction"], r["framing"])][r["degradation"]] = r["metric"]

    fig, axes = plt.subplots(1, len(PANELS), figsize=(5 * len(PANELS), 4.4), squeeze=False)
    x = list(range(len(DEG_ORDER)))

    for ax, direction in zip(axes[0], PANELS):
        is_datagrams = direction == "datagrams"
        for framing in FRAMINGS:
            series = index.get((direction, framing))
            if not series:
                continue
            xs, avg, lo, hi = [], [], [], []
            for xi, deg in enumerate(DEG_ORDER):
                st = series.get(deg)
                if st is None:
                    continue
                xs.append(xi)
                avg.append(st["avg"])
                lo.append(st["min"])
                hi.append(st["max"])
            if not xs:
                continue
            (line,) = ax.plot(xs, avg, marker="o", label=framing)
            ax.fill_between(xs, lo, hi, color=line.get_color(), alpha=0.15)
        ax.set_title("datagram delivery" if is_datagrams else direction)
        ax.set_xticks(x)
        ax.set_xticklabels(DEG_ORDER)
        ax.set_xlabel("link condition")
        ax.grid(True, which="both", alpha=0.3)
        ax.legend()
        if is_datagrams:
            ax.set_ylabel("delivery (%)")
            ax.set_ylim(0, 105)
        else:
            ax.set_ylabel("throughput (kbit/s)")
            # Throughput spans a wide range across conditions, so a log y-axis
            # keeps the slower levels legible.
            ax.set_yscale("log")

    fig.suptitle("iroh relay transport: throughput and datagram delivery vs link condition, by framing")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    print(f"wrote {path}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("infile", nargs="?", help="raw RUNDOWN CSV (default: stdin)")
    ap.add_argument("-o", "--out", default="rundown.png", help="output PNG path")
    ap.add_argument("-c", "--csv", default="results-agg.csv", help="aggregate CSV path")
    args = ap.parse_args()

    src = open(args.infile) if args.infile else sys.stdin
    metric, setup, failures = read_raw(src)
    if args.infile:
        src.close()

    rows = aggregate(metric, setup, failures)
    if not rows:
        sys.exit("no RUNDOWN rows found on input")

    write_csv(rows, args.csv)
    plot(rows, args.out)


if __name__ == "__main__":
    main()
