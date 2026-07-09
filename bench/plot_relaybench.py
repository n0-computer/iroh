#!/usr/bin/env python3
"""Plot a `run_relaybench.py` aggregated CSV as small multiples.

One panel per link condition (each with its own linear scale, because goodput
spans ~3 Gbit on LAN down to ~0.5 Mbit on 3G), a bar per relay transport with a
min..max whisker and a value label, and a dashed reference line at the WebSocket
(`ws`) result so the WebTransport bars can be read against the baseline.

usage: bench/plot_relaybench.py [results.csv] [out.png]
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# Fixed categorical order and colors (Okabe-Ito, colorblind-safe; validated with
# the dataviz skill's checker, CVD dE ~37). ws is the baseline blue; the wt
# family takes the warm hues.
FRAMINGS = ["ws", "wt-uni", "wt-singlestream", "wt-datagram"]
COLORS = {
    "ws": "#0072B2",
    "wt-uni": "#E69F00",
    "wt-singlestream": "#009E73",
    "wt-datagram": "#D55E00",
}
DEGRADATIONS = ["localhost", "lan", "wifi", "4g", "3g"]
DEG_TITLE = {
    "localhost": "localhost  (loopback, no namespacing)",
    "lan": "LAN  (clean)",
    "wifi": "WiFi  (5ms, 2ms jitter, 0.1% loss)",
    "4g": "4G  (25ms, 8ms jitter, 0.5% loss)",
    "3g": "3G  (100ms, 30ms jitter, 2% loss, 2Mbit)",
}

INK = "#1a1a1a"
MUTED = "#6b6b6b"
GRID = "#e6e6e4"
SURFACE = "#fcfcfb"


def fmt_rate(v: float) -> str:
    """Human Mbit/s label: Gbit for large values."""
    if v >= 1000:
        return f"{v / 1000:.1f}G"
    if v >= 100:
        return f"{v:.0f}"
    if v >= 10:
        return f"{v:.1f}"
    return f"{v:.2f}"


def load(path: Path) -> dict[tuple[str, str], dict]:
    rows: dict[tuple[str, str], dict] = {}
    with path.open() as f:
        for r in csv.DictReader(f):
            rows[(r["framing"], r["degradation"])] = r
    return rows


def main() -> None:
    csv_path = Path(sys.argv[1] if len(sys.argv) > 1 else "bench/relaybench-results.csv")
    out_path = Path(sys.argv[2] if len(sys.argv) > 2 else "bench/relaybench-results.png")
    rows = load(csv_path)

    degs = [d for d in DEGRADATIONS if any((fr, d) in rows for fr in FRAMINGS)]
    frms = [fr for fr in FRAMINGS if any((fr, d) in rows for d in degs)]

    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.size": 10,
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "text.color": INK,
            "axes.labelcolor": MUTED,
            "xtick.color": MUTED,
            "ytick.color": MUTED,
        }
    )

    ncol = 2
    nrow = (len(degs) + ncol - 1) // ncol
    fig, axes = plt.subplots(nrow, ncol, figsize=(11, 4.4 * nrow))
    axes = axes.flatten() if hasattr(axes, "flatten") else [axes]

    for ax, deg in zip(axes, degs):
        present = [fr for fr in frms if (fr, deg) in rows]
        means, lo_err, hi_err, colors, labels = [], [], [], [], []
        los, his, fails, partials = [], [], [], []
        for fr in present:
            r = rows[(fr, deg)]
            mean = float(r["mean_mbps"])
            lo = float(r.get("min_mbps", mean) or mean)
            hi = float(r.get("max_mbps", mean) or mean)
            n = int(r.get("n", 0) or 0)
            nfail = int(r.get("failures", 0) or 0)
            means.append(mean)
            los.append(lo)
            his.append(hi)
            lo_err.append(max(0.0, mean - lo))
            hi_err.append(max(0.0, hi - mean))
            colors.append(COLORS[fr])
            labels.append(fr)
            fails.append(nfail > 0 and n == 0)
            # note partial failures (some runs completed, some did not)
            partials.append(f" {n}/{n + nfail} ok" if nfail > 0 and n > 0 else "")

        x = range(len(present))
        bars = ax.bar(
            x,
            means,
            width=0.68,
            color=colors,
            edgecolor=SURFACE,
            linewidth=1.5,
            zorder=3,
        )
        # min..max whisker.
        ax.errorbar(
            x,
            means,
            yerr=[lo_err, hi_err],
            fmt="none",
            ecolor=MUTED,
            elinewidth=1.2,
            capsize=3,
            zorder=4,
        )

        # ws baseline reference line across the panel.
        if ("ws", deg) in rows:
            ws_mean = float(rows[("ws", deg)]["mean_mbps"])
            ax.axhline(ws_mean, color=COLORS["ws"], linestyle="--", linewidth=1.0, alpha=0.6, zorder=2)

        top = max(m + h for m, h in zip(means, hi_err)) if means else 1e-9
        top = max(top, 1e-9)
        ax.set_ylim(0, top * 1.42)
        for xi, (mean, lo, hi_v, herr, fr, failed, partial) in enumerate(
            zip(means, los, his, hi_err, present, fails, partials)
        ):
            if failed:
                ax.text(xi, top * 0.03, "all runs\nfailed", ha="center", va="bottom", color=COLORS[fr], fontsize=8.5, fontweight="bold", linespacing=1.2)
                continue
            # Label block above the whisker cap: avg (prominent), then the
            # min..max range, then the ratio vs the ws baseline (wt only). The
            # whisker shows the same min..max visually.
            y = mean + herr + top * 0.03
            ax.text(xi, y, f"avg {fmt_rate(mean)}", ha="center", va="bottom", color=INK, fontsize=9, fontweight="bold")
            sub = f"{fmt_rate(lo)}-{fmt_rate(hi_v)}"
            if fr != "ws" and ("ws", deg) in rows:
                ws_mean = float(rows[("ws", deg)]["mean_mbps"])
                if ws_mean > 0:
                    sub += f"\n{mean / ws_mean:.2f}x vs ws"
            if partial:
                sub += f"\n({partial.strip()})"
            ax.text(xi, y + top * 0.075, sub, ha="center", va="bottom", color=MUTED, fontsize=8, linespacing=1.3)

        ax.set_title(DEG_TITLE.get(deg, deg), fontsize=11, color=INK, loc="left", pad=8)
        ax.set_xticks(list(x))
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_ylabel("goodput (Mbit/s)")
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: fmt_rate(v) if v else "0"))
        ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
        ax.set_axisbelow(True)
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        for spine in ("left", "bottom"):
            ax.spines[spine].set_color(GRID)

    for ax in axes[len(degs):]:
        ax.set_visible(False)

    fig.suptitle(
        "Relay goodput: WebSocket vs WebTransport framings, by link condition",
        fontsize=13,
        color=INK,
        x=0.02,
        ha="left",
        y=0.995,
        fontweight="bold",
    )
    fig.text(
        0.02,
        0.965,
        "download, real-process benchmark; bars = mean of N runs, whisker = min..max, "
        "dashed line = ws baseline, Nx = vs ws",
        fontsize=9,
        color=MUTED,
        ha="left",
    )
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(out_path, dpi=140)
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
