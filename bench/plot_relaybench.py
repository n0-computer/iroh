#!/usr/bin/env python3
"""Plot a `run_relaybench.py` aggregated CSV as small multiples.

One panel per link condition (each with its own linear scale, because goodput
spans ~3 Gbit on LAN down to ~0.5 Mbit on 3G), a bar per relay transport with a
min..max whisker and value labels, and a dashed reference line at the WebSocket
(`ws`) result so the WebTransport bars can be read against the baseline.

If the CSV carries a `config` column with more than one value (from
`run_relaybench.py --configs tuned,default` / `--full-matrix`), each `wt-*`
framing gets two bars -- tuned (solid) and default (hatched) -- so the effect of
the WebTransport hop tuning is visible directly; `ws` keeps a single bar.

usage: bench/plot_relaybench.py [results.csv] [out.png] [--mode MODE] [--subtitle TEXT]
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
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
# WebTransport hop config: tuned = solid fill, default = hatched (same colour).
CONFIG_ORDER = ["tuned", "default"]
HATCH = {"tuned": "", "default": "////"}
CONFIG_LEGEND = {
    "tuned": "tuned (BBR + reorder-tolerant loss detection)",
    "default": "default (Cubic, RFC 9002 thresholds)",
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


def load(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader(f))


def bar_of(row: dict) -> dict:
    mean = float(row["mean_mbps"])
    lo = float(row.get("min_mbps", mean) or mean)
    hi = float(row.get("max_mbps", mean) or mean)
    n = int(row.get("n", 0) or 0)
    nfail = int(row.get("failures", 0) or 0)
    return {
        "framing": row["framing"],
        "config": row.get("config"),
        "mean": mean,
        "lo": lo,
        "hi": hi,
        "failed": nfail > 0 and n == 0,
        "partial": f"{n}/{n + nfail} ok" if nfail > 0 and n > 0 else "",
    }


def main() -> None:
    args = sys.argv[1:]

    def opt(name: str, default: str = "") -> str:
        if name in args:
            i = args.index(name)
            val = args[i + 1] if i + 1 < len(args) else default
            del args[i : i + 2]
            return val
        return default

    subtitle = opt("--subtitle")
    mode = opt("--mode")
    csv_path = Path(args[0] if len(args) > 0 else "bench/relaybench-results.csv")
    out_path = Path(args[1] if len(args) > 1 else "bench/relaybench-results.png")

    rows = load(csv_path)
    modes_present = sorted({r.get("mode", "download") for r in rows})
    if not mode:
        mode = modes_present[0] if len(modes_present) == 1 else "download"
    rows = [r for r in rows if r.get("mode", "download") == mode]
    if not rows:
        sys.exit(f"no rows for mode={mode} (modes present: {', '.join(modes_present)})")

    configs = [c for c in CONFIG_ORDER if any(r.get("config") == c for r in rows)]
    if not configs:
        configs = [None]  # CSV without a config column
    grouped = len(configs) > 1

    # lookup[(framing, degradation, config)] -> bar
    lookup = {(r["framing"], r["degradation"], r.get("config")): bar_of(r) for r in rows}
    degs = [d for d in DEGRADATIONS if any(k[1] == d for k in lookup)]

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
    fig, axes = plt.subplots(nrow, ncol, figsize=(11, 4.6 * nrow))
    axes = axes.flatten() if hasattr(axes, "flatten") else [axes]

    for ax, deg in zip(axes, degs):
        # Ordered bars: each present framing, then each present config for it
        # (ws typically only one). Track x positions and per-framing group spans.
        bars, xs, group_center, group_label = [], [], [], []
        cursor = 0.0
        for fr in FRAMINGS:
            fr_cfgs = [c for c in configs if (fr, deg, c) in lookup]
            if not fr_cfgs:
                continue
            start = cursor
            for c in fr_cfgs:
                bars.append(lookup[(fr, deg, c)])
                xs.append(cursor)
                cursor += 1.0
            group_center.append((start + cursor - 1.0) / 2.0)
            group_label.append(fr)
            cursor += 0.6  # gap between framing groups
        if not bars:
            ax.set_visible(False)
            continue

        top = max((b["mean"] + (b["hi"] - b["mean"]) for b in bars), default=1e-9)
        top = max(top, 1e-9)
        ax.set_ylim(0, top * (1.32 if grouped else 1.42))

        ws_mean = lookup[("ws", deg, "tuned")]["mean"] if ("ws", deg, "tuned") in lookup else (
            lookup[("ws", deg, None)]["mean"] if ("ws", deg, None) in lookup else None
        )
        if ws_mean is not None:
            ax.axhline(ws_mean, color=COLORS["ws"], linestyle="--", linewidth=1.0, alpha=0.6, zorder=2)

        for b, x in zip(bars, xs):
            ax.bar(
                x, b["mean"], width=0.9, color=COLORS[b["framing"]], edgecolor=SURFACE,
                linewidth=1.0, hatch=HATCH.get(b["config"], ""), zorder=3,
            )
            ax.errorbar(
                x, b["mean"], yerr=[[b["mean"] - b["lo"]], [b["hi"] - b["mean"]]],
                fmt="none", ecolor=MUTED, elinewidth=1.1, capsize=3, zorder=4,
            )
            if b["failed"]:
                ax.text(x, top * 0.03, "all runs\nfailed", ha="center", va="bottom",
                        color=COLORS[b["framing"]], fontsize=7.5, fontweight="bold", linespacing=1.2)
                continue
            y = b["hi"] + top * 0.03
            ax.text(x, y, f"avg {fmt_rate(b['mean'])}", ha="center", va="bottom",
                    color=INK, fontsize=8, fontweight="bold")
            extra = []
            if not grouped:
                extra.append(f"{fmt_rate(b['lo'])}-{fmt_rate(b['hi'])}")
                if b["framing"] != "ws" and ws_mean:
                    extra.append(f"{b['mean'] / ws_mean:.2f}x vs ws")
            else:
                # On the tuned bar of a wt framing, show the tuned/default gain.
                if b["framing"] != "ws" and b["config"] == "tuned":
                    dflt = lookup.get((b["framing"], deg, "default"))
                    if dflt and dflt["mean"] > 0:
                        extra.append(f"{b['mean'] / dflt['mean']:.1f}x tuned")
            if b["partial"]:
                extra.append(f"({b['partial']})")
            if extra:
                ax.text(x, y + top * 0.055, "\n".join(extra), ha="center", va="bottom",
                        color=MUTED, fontsize=7.5, linespacing=1.3)

        ax.set_title(DEG_TITLE.get(deg, deg), fontsize=11, color=INK, loc="left", pad=8)
        ax.set_xticks(group_center)
        ax.set_xticklabels(group_label, fontsize=9)
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
        fontsize=13, color=INK, x=0.02, ha="left", y=0.995, fontweight="bold",
    )
    caption = (
        "real-process benchmark; bars = mean of N runs, whisker = min..max, "
        "dashed line = ws baseline"
    )
    if subtitle:
        caption = f"{subtitle}\n{caption}"
    fig.text(0.02, 0.965, caption, fontsize=9, color=MUTED, ha="left", va="top", linespacing=1.5)

    if grouped:
        handles = [
            Patch(facecolor=MUTED, hatch=HATCH[c], edgecolor="white", label=CONFIG_LEGEND[c])
            for c in configs
        ]
        fig.legend(handles=handles, loc="upper right", bbox_to_anchor=(0.99, 0.985),
                   frameon=False, fontsize=8.5)

    fig.tight_layout(rect=(0, 0, 1, 0.93 if subtitle else 0.94))
    fig.savefig(out_path, dpi=140)
    print(f"wrote {out_path} (mode={mode}, configs={','.join(str(c) for c in configs)})")


if __name__ == "__main__":
    main()
