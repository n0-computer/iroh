#!/usr/bin/env python3
"""Sequential driver for the `relay_bench` example.

Sweeps a matrix of relay transports x link conditions x transfer directions,
running each cell N times, strictly one at a time (nothing else should be
running: the numbers are throughput and any competing load skews them). Each run
spawns the release-built `relay_bench` binary, which builds a patchbay lab and
runs the real `transfer` example in-namespace over the relay. The `RELAYBENCH`
summary line is parsed for goodput; per-run stderr (the transfer processes'
trace logs) is saved under the log dir so a slow run can be inspected.

This is the tool for iterating on the WebSocket-vs-WebTransport throughput gap:
tune the matrix, set a steady-state --duration, add RUST_LOG for traces.

Linux only (patchbay uses unprivileged user namespaces, no sudo).

Examples:
  # quick ws-vs-wt steady-state download comparison on wifi, 3 runs each
  bench/run_relaybench.py --framings ws,wt-uni,wt-singlestream \\
    --degradations wifi --modes download --duration 8 --runs 3

  # full matrix with datagrams and traces
  bench/run_relaybench.py --duration 10 --runs 3 \\
    --rust-log 'bench_stats=info,iroh_relay=debug'
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Default directory holding the release `transfer` and `relay_bench` binaries:
# $BENCH_BINS if set, else the common `~/rust_target` cargo target dir's examples
# dir. Override either binary individually with --transfer-bin / --relay-bench-bin.
DEFAULT_TARGET = (
    Path(os.environ["BENCH_BINS"])
    if os.environ.get("BENCH_BINS")
    else Path.home() / "rust_target" / "release" / "examples"
)

ALL_FRAMINGS = ["ws", "wt-uni", "wt-datagram", "wt-singlestream"]
# "localhost" is a pseudo-condition: relay_bench runs it with --localhost (no
# patchbay namespaces/impairment) instead of --degradation.
ALL_DEGRADATIONS = ["localhost", "lan", "wifi", "4g", "3g"]
ALL_MODES = ["download", "upload", "bidi"]
# WebTransport relay-hop transport config. "tuned" is the fix (BBR +
# reorder-tolerant loss detection); "default" reverts the congestion controller
# and reordering thresholds to the noq defaults via IROH_RELAY_H3_DEFAULT_TRANSPORT.
# Only affects the wt-* framings; ws does not use the WebTransport hop.
ALL_CONFIGS = ["tuned", "default"]
DEFAULT_TRANSPORT_ENV = "IROH_RELAY_H3_DEFAULT_TRANSPORT"

# The line relay_bench prints on success is a space-separated list of key=value
# tokens after the RELAYBENCH marker, e.g.
#   RELAYBENCH bytes=4194304 secs=0.303 mbps=110.61 mode=download degradation=Wifi
#     udp_tx_datagrams=.. udp_tx_ios=.. udp_rx_datagrams=.. udp_rx_ios=..
#     lost_packets=.. lost_bytes=.. cwnd=.. rtt_us=..
RESULT_MARKER = "RELAYBENCH "
# Numeric stat fields to average across runs and report in the CSV.
STAT_FIELDS = [
    "mbps",
    "udp_tx_datagrams",
    "udp_tx_ios",
    "udp_rx_datagrams",
    "udp_rx_ios",
    "lost_packets",
    "lost_bytes",
    "cwnd",
    "rtt_us",
]


def parse_result(line: str) -> dict | None:
    """Parse a RELAYBENCH result line into a dict of key->value (floats where
    numeric), or None if the marker is absent."""
    idx = line.find(RESULT_MARKER)
    if idx < 0:
        return None
    fields = {}
    for tok in line[idx + len(RESULT_MARKER) :].split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        try:
            fields[k] = float(v)
        except ValueError:
            fields[k] = v
    return fields


@dataclass
class Cell:
    framing: str
    degradation: str
    mode: str
    config: str = "tuned"
    runs: list[dict] = field(default_factory=list)  # parsed result per success
    failures: int = 0

    @property
    def key(self) -> str:
        return f"{self.config}/{self.framing}/{self.degradation}/{self.mode}"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--relay-bench-bin",
        type=Path,
        default=DEFAULT_TARGET / "relay_bench",
        help="path to the release relay_bench binary",
    )
    p.add_argument(
        "--transfer-bin",
        type=Path,
        default=DEFAULT_TARGET / "transfer",
        help="path to the release transfer binary (passed to relay_bench)",
    )
    p.add_argument(
        "--framings",
        default=",".join(ALL_FRAMINGS),
        help=f"comma-separated relay transports (of {','.join(ALL_FRAMINGS)})",
    )
    p.add_argument(
        "--degradations",
        default="wifi,4g,3g",
        help=f"comma-separated link conditions (of {','.join(ALL_DEGRADATIONS)})",
    )
    p.add_argument(
        "--modes",
        default="download",
        help=f"comma-separated directions (of {','.join(ALL_MODES)})",
    )
    p.add_argument(
        "--configs",
        default="tuned",
        help=f"comma-separated WebTransport hop configs (of {','.join(ALL_CONFIGS)}); "
        "'default' reverts the congestion controller + reordering thresholds to the "
        "noq defaults. wt-* only; ws is run once.",
    )
    p.add_argument(
        "--full-matrix",
        action="store_true",
        help="run every framing x degradation x mode x {tuned,default} and render a "
        "grouped tuned-vs-default chart per mode. Long; tune --runs/--duration.",
    )
    dur = p.add_mutually_exclusive_group()
    dur.add_argument(
        "--duration",
        type=int,
        default=8,
        help="steady-state transfer duration in seconds (default 8)",
    )
    dur.add_argument(
        "--size", type=int, help="fixed transfer size in bytes (instead of --duration)"
    )
    p.add_argument("--runs", type=int, default=3, help="repetitions per cell")
    p.add_argument("--mtu", type=int, default=1400, help="link MTU")
    p.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="overall timeout per run in seconds (passed to relay_bench); "
        "defaults to duration+60 in duration mode, else 180",
    )
    p.add_argument(
        "--rust-log",
        default=os.environ.get("RUST_LOG"),
        help="RUST_LOG for the transfer processes (inherited via env)",
    )
    p.add_argument(
        "--log-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "logs-relaybench",
        help="directory for per-run stderr trace logs",
    )
    p.add_argument(
        "--csv",
        type=Path,
        default=Path(__file__).resolve().parent / "relaybench-raw.csv",
        help="raw per-run CSV output path",
    )
    p.add_argument(
        "--build",
        action="store_true",
        help="release-build transfer and relay_bench before running",
    )
    return p.parse_args()


def split_csv(value: str, allowed: list[str], what: str) -> list[str]:
    items = [x.strip() for x in value.split(",") if x.strip()]
    bad = [x for x in items if x not in allowed]
    if bad:
        sys.exit(f"unknown {what}: {', '.join(bad)} (allowed: {', '.join(allowed)})")
    return items


def build_binaries() -> None:
    print("building transfer + relay_bench (release)...", file=sys.stderr)
    subprocess.run(
        [
            "cargo", "build", "--release", "-p", "iroh",
            "--features", "test-utils",
            "--example", "transfer", "--example", "relay_bench",
        ],
        check=True,
    )


def run_cell(cell: Cell, args: argparse.Namespace, log_dir: Path) -> None:
    """Run one cell `args.runs` times, appending mbps samples to the cell."""
    for run in range(1, args.runs + 1):
        cmd = [
            str(args.relay_bench_bin),
            "--transfer-bin", str(args.transfer_bin),
            "--mode", cell.mode,
            "--mtu", str(args.mtu),
            "--timeout", str(args.timeout),
        ]
        # "localhost" is the no-namespacing baseline: --localhost, no degradation.
        if cell.degradation == "localhost":
            cmd += ["--localhost"]
        else:
            cmd += ["--degradation", cell.degradation]
        if args.size is not None:
            cmd += ["--size", str(args.size)]
        else:
            cmd += ["--duration", str(args.duration)]
        cmd += ["--", "--relay-transport", cell.framing]
        # Force the WebTransport transport for wt-* framings so the run measures
        # WebTransport and never silently falls back to WebSocket (which the
        # client would otherwise do when its handshake wins the race, e.g. on a
        # fast loopback path).
        if cell.framing != "ws":
            cmd += ["--webtransport-only"]

        env = dict(os.environ)
        if args.rust_log:
            env["RUST_LOG"] = args.rust_log
        # "default" config reverts the WebTransport hop's CC + reordering
        # thresholds to the noq defaults; "tuned" is the ambient (fixed) build.
        if cell.config == "default":
            env[DEFAULT_TRANSPORT_ENV] = "1"
        else:
            env.pop(DEFAULT_TRANSPORT_ENV, None)

        log_path = (
            log_dir
            / f"{cell.config}_{cell.framing}_{cell.degradation}_{cell.mode}_run{run}.log"
        )
        label = f"{cell.key} run {run}/{args.runs}"
        print(f"  {label} ...", end="", flush=True, file=sys.stderr)

        # A run can hang if a framing stalls; bound it a little above the
        # relay_bench internal timeout so its own error message wins the race.
        wall_timeout = args.timeout + 30
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=wall_timeout,
            )
        except subprocess.TimeoutExpired as e:
            elapsed = time.monotonic() - start
            log_path.write_text((e.stderr or "") if isinstance(e.stderr, str) else "")
            cell.failures += 1
            print(f" TIMEOUT after {elapsed:.0f}s (log: {log_path.name})", file=sys.stderr)
            continue

        elapsed = time.monotonic() - start
        log_path.write_text(proc.stderr)

        result = parse_result(proc.stdout)
        if result and proc.returncode == 0:
            cell.runs.append(result)
            print(f" {result.get('mbps', 0):.1f} Mbit ({elapsed:.0f}s)", file=sys.stderr)
        else:
            cell.failures += 1
            tail = proc.stdout.strip().splitlines()[-1:] or [""]
            print(
                f" FAILED rc={proc.returncode} ({elapsed:.0f}s) {tail[0]}"
                f" (log: {log_path.name})",
                file=sys.stderr,
            )


def summarize(cell: Cell) -> dict[str, str]:
    mbps = [r.get("mbps", 0.0) for r in cell.runs]
    if mbps:
        mean = statistics.mean(mbps)
        med = statistics.median(mbps)
        lo = min(mbps)
        hi = max(mbps)
        sd = statistics.stdev(mbps) if len(mbps) > 1 else 0.0
    else:
        mean = med = lo = hi = sd = 0.0
    # cv%% = the coefficient of variation, a scale-free measure of run-to-run
    # spread; median is more robust to an outlier run than the mean.
    row = {
        "framing": cell.framing,
        "degradation": cell.degradation,
        "mode": cell.mode,
        "config": cell.config,
        "n": str(len(cell.runs)),
        "failures": str(cell.failures),
        "mean_mbps": f"{mean:.2f}",
        "median_mbps": f"{med:.2f}",
        "min_mbps": f"{lo:.2f}",
        "max_mbps": f"{hi:.2f}",
        "stddev_mbps": f"{sd:.2f}",
        "cv_pct": f"{100.0 * sd / mean:.1f}" if mean else "0",
    }
    # Mean of each numeric stat field across successful runs.
    for fld in STAT_FIELDS:
        if fld == "mbps":
            continue
        vals = [r.get(fld) for r in cell.runs if isinstance(r.get(fld), (int, float))]
        row[fld] = f"{statistics.mean(vals):.0f}" if vals else "0"
    # Derived: mean GSO/GRO send/recv batch size and loss rate. A batch near 1.0
    # means no send/receive syscall batching on the tunneled p2p connection.
    tx_d, tx_i = float(row["udp_tx_datagrams"]), float(row["udp_tx_ios"])
    rx_d, rx_i = float(row["udp_rx_datagrams"]), float(row["udp_rx_ios"])
    row["tx_batch"] = f"{tx_d / tx_i:.2f}" if tx_i else "0"
    row["rx_batch"] = f"{rx_d / rx_i:.2f}" if rx_i else "0"
    total = tx_d + rx_d
    row["loss_pct"] = f"{100.0 * float(row['lost_packets']) / total:.2f}" if total else "0"
    return row


def render_charts(csv_path: Path, modes: list[str]) -> None:
    """Render a grouped tuned-vs-default chart per mode from the aggregated CSV."""
    plot = Path(__file__).resolve().parent / "plot_relaybench.py"
    if not plot.is_file():
        print(f"(no plot script at {plot}; skipping charts)", file=sys.stderr)
        return
    subtitle = (
        "WebTransport relay hop: tuned (BBR + reorder-tolerant loss detection) "
        "vs default (Cubic)"
    )
    for mode in modes:
        out = csv_path.with_name(f"{csv_path.stem}-{mode}.png")
        subprocess.run(
            [sys.executable, str(plot), str(csv_path), str(out),
             "--mode", mode, "--subtitle", f"{mode} -- {subtitle}"],
            check=False,
        )


def print_table(rows: list[dict[str, str]]) -> None:
    cols = [
        ("config", 8),
        ("framing", 16),
        ("degradation", 11),
        ("mode", 9),
        ("n", 3),
        ("mean_mbps", 10),
        ("median_mbps", 11),
        ("cv_pct", 6),
        ("tx_batch", 8),
        ("rx_batch", 8),
        ("loss_pct", 8),
        ("rtt_us", 8),
        ("failures", 8),
    ]
    header = "  ".join(name.ljust(width) for name, width in cols)
    print("\n" + header)
    print("  ".join("-" * width for _, width in cols))
    for r in rows:
        print("  ".join(str(r.get(name, "")).ljust(width) for name, width in cols))


def main() -> None:
    args = parse_args()
    if sys.platform != "linux":
        sys.exit("relay_bench requires linux (patchbay uses user namespaces)")

    if args.full_matrix:
        args.framings = ",".join(ALL_FRAMINGS)
        args.degradations = ",".join(ALL_DEGRADATIONS)
        args.modes = ",".join(ALL_MODES)
        args.configs = ",".join(ALL_CONFIGS)

    framings = split_csv(args.framings, ALL_FRAMINGS, "framing")
    degradations = split_csv(args.degradations, ALL_DEGRADATIONS, "degradation")
    modes = split_csv(args.modes, ALL_MODES, "mode")
    configs = split_csv(args.configs, ALL_CONFIGS, "config")

    # A duration-bounded transfer finishes in `duration` plus setup, so a run
    # that has not finished well past that is stuck: bound the wait tightly so a
    # stuck cell does not burn the default 180s. Cleanup on timeout is handled by
    # relay_bench's kill guard.
    if args.timeout is None:
        args.timeout = args.duration + 60 if args.size is None else 180

    if args.build:
        build_binaries()
    for binp, what in [(args.relay_bench_bin, "relay_bench"), (args.transfer_bin, "transfer")]:
        if not binp.is_file():
            sys.exit(f"{what} binary not found: {binp} (build with --build?)")

    args.log_dir.mkdir(parents=True, exist_ok=True)

    # Plan the cells. ws does not use the WebTransport hop, so the config knob
    # does not affect it -- run it once (under the first config) rather than
    # measuring identical WebSocket runs twice.
    plan: list[tuple[str, str, str, str]] = []  # (config, framing, degradation, mode)
    for config in configs:
        for framing in framings:
            if framing == "ws" and config != configs[0]:
                continue
            for degradation in degradations:
                for mode in modes:
                    plan.append((config, framing, degradation, mode))

    limit = f"--size {args.size}" if args.size is not None else f"--duration {args.duration}"
    print(
        f"matrix: {len(framings)} framing x {len(degradations)} degradation x "
        f"{len(modes)} mode x {len(configs)} config = {len(plan)} cells, "
        f"{args.runs} run(s) each, {limit}",
        file=sys.stderr,
    )

    cells: list[Cell] = []
    for idx, (config, framing, degradation, mode) in enumerate(plan, 1):
        cell = Cell(framing, degradation, mode, config)
        print(f"[{idx}/{len(plan)}] {cell.key}", file=sys.stderr)
        run_cell(cell, args, args.log_dir)
        cells.append(cell)

    rows = [summarize(c) for c in cells]
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    with args.csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print_table(rows)
    print(f"\nraw CSV: {args.csv}", file=sys.stderr)
    print(f"logs:    {args.log_dir}", file=sys.stderr)

    # With more than one config, render the grouped tuned-vs-default chart(s).
    if len(configs) > 1:
        render_charts(args.csv, modes)


if __name__ == "__main__":
    main()
