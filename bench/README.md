# Relay throughput benchmarks

Tools for measuring iroh relay goodput and comparing the **WebSocket** relay
transport against the three **WebTransport** (H3/QUIC) framings, plus the saved
results that motivated the WebTransport hop tuning on this branch.

## Headline

The WebTransport relay transport used to be 3-4x slower than WebSocket. The
cause was the relay's H3/QUIC hop misreading a jittery last-mile link's packet
reordering as loss (QUIC's fixed reordering thresholds) -- so the reliable relay
stream retransmitted ~40% of packets, collapsing goodput and inflating RTT.
Raising the packet- and time-reordering thresholds fixes that, and with a
loss-based **Cubic** congestion controller on the hop (the same controller ws'
TCP hop uses) the reliable single-stream framing (`wt-singlestream`) reaches
WebSocket goodput on every link:

| link | ws | wt-singlestream (tuned) |
| ---- | -- | ----------------------- |
| localhost | 1.5 Gbit | 1.7 Gbit (**1.1x**) |
| lan  | fastest (kernel TCP) | 0.75x (double-QUIC overhead at Gbit) |
| wifi | ~130 Mbit | ~130 Mbit (**parity**) |
| 4g   | ~14 Mbit | ~21 Mbit (**1.5x**, lower RTT) |
| 3g   | ~1 Mbit | ~1 Mbit (ballpark; noisy) |

Note on the congestion controller: BBR3 was tried on the hop first, but its
bandwidth estimate collapses on the tunnelled hop (the reliable tunnel looks
app-limited whenever the inner connection is flow-control blocked), pinning the
hop cwnd low and throttling goodput to ~half of ws. Cubic -- what ws already uses
-- fills the link. The reorder thresholds are the load-bearing part: a Cubic hop
*without* them collapses on spurious loss just as badly. See the overnight
investigation in [`results/overnight/claude-report.md`](results/overnight/claude-report.md)
and [`results/overnight/realistic-matrix-download.png`](results/overnight/realistic-matrix-download.png).

The `wt-uni` framing (one uni stream per message, the current protocol default)
stays ~2x slower: independent per-message streams deliver the tunnelled iroh
packets reordered, which the inner connection reads as loss. `wt-singlestream`
(`UniOrdered`) is ordered and does not, so it is the framing to use over the
relay; switching the default to it is recommended (see the report for the
wire-compat caveat).

The fix lives in `iroh-relay`:
`protos/h3_streams.rs::configure_relay_h3_transport` (the shared transport
config + the `WT_REORDER_*` / `WT_STREAM_RECEIVE_WINDOW` / `H3_MIN_MTU` /
`MAX_CONCURRENT_UNI_STREAMS` constants), applied by both `client/h3_conn.rs` and
`server/h3_server.rs`.

## Results

Saved under [`results/`](results/) -- see [`results/bench.md`](results/bench.md)
for the full setup, link-condition parameters, per-cell numbers, and the
analysis (why WebSocket loss-collapses on 4g, the wt-datagram behaviour, the
WebSocket-fallback caveat).

Two same-session sweeps that differ only in the WebTransport hop's QUIC config
(toggled with the `IROH_RELAY_H3_DEFAULT_TRANSPORT` env var), 3 runs x 10s,
download, across `localhost` + `lan`/`wifi`/`4g`/`3g`:

- **[results/wt-tuned-3x10s.png](results/wt-tuned-3x10s.png)**
  ([csv](results/wt-tuned-3x10s.csv)) -- BBR + reorder-tolerant loss detection
  (the fix). The authoritative result.
- **[results/wt-default-3x10s.png](results/wt-default-3x10s.png)**
  ([csv](results/wt-default-3x10s.csv)) -- default Cubic + RFC 9002 reordering
  thresholds (baseline). Shows what the tuning buys: wifi wt-uni 31 -> 125 Mbit
  (4.1x), 4g wt-uni 2.9 -> 25 Mbit (8.7x), 3g wt-uni failing -> working.

Caveat baked into those images: the `localhost`/`lan` cells run at 1-3 Gbit over
loopback/veth, where goodput is bounded by single-core CPU and the scheduler,
not the network, so their absolute numbers are noisy and order-sensitive (`ws`,
which is unaffected by the WebTransport toggle, still swings ~890 vs ~1370 Mbit
between the two sets). The impaired-link cells are rate/latency-bound and
reproduce closely; that is where the comparison is meaningful.

## The primary harness: `relay_bench` + `run_relaybench.py`

`iroh/examples/relay_bench.rs` builds a patchbay network (linux, rootless user
namespaces, no sudo) -- a relay and two peers behind symmetric NATs -- and runs
the release `transfer` example as a **real OS process in each peer's network
namespace**, over an in-process relay. No in-process test harness as a variable;
supports long duration-based steady-state runs. It prints a `RELAYBENCH` line
with goodput plus the tunneled p2p connection's loss / RTT / send-recv batch
counters.

`run_relaybench.py` drives a strictly sequential sweep (framing x link-condition
x direction, N runs each) into an aggregated CSV; `plot_relaybench.py` renders it
as the small-multiples PNGs above.

```bash
# build both examples (transfer is the relay CLIENT -- always rebuild both)
cargo build --release -p iroh --features test-utils --example transfer --example relay_bench

# a sweep (writes the CSV; --build rebuilds both examples for you)
bench/run_relaybench.py --framings ws,wt-uni,wt-singlestream,wt-datagram \
  --degradations localhost,wifi,4g,3g --modes download --duration 10 --runs 3 \
  --csv bench/results/my-run.csv
bench/plot_relaybench.py bench/results/my-run.csv bench/results/my-run.png \
  --subtitle "my run"
```

Notes:

- **Framings** are the `transfer --relay-transport` values: `ws`, `wt-uni`
  (one uni stream per message), `wt-singlestream` (one long-lived ordered uni
  stream per direction), `wt-datagram` (one QUIC datagram per message).
- **`localhost`** is a pseudo-condition: `relay_bench --localhost` runs
  everything on loopback with no patchbay namespaces/impairment, a no-namespacing
  baseline.
- **Forced WebTransport.** The driver passes `transfer --webtransport-only` for
  every `wt-*` run, so the client does not race (and silently fall back to)
  WebSocket. Without it, on a fast path the WebSocket handshake wins the race and
  a `wt-*` request is served over WebSocket -- so a WebTransport benchmark would
  actually measure WebSocket. (This replaces the old source-patching hack.)
- **Binary location.** The driver looks for `transfer` and `relay_bench` in
  `$BENCH_BINS` if set, else `~/rust_target/release/examples`. Override either
  with `--transfer-bin` / `--relay-bench-bin`, or rebuild both with `--build`.
- **Keep the machine idle.** The WebTransport connect races a timing-sensitive
  QUIC handshake that flakes under CPU contention; run sweeps sequentially with
  nothing else running.
- **Tracing.** `--rust-log 'iroh_relay=debug' --log-dir /tmp/rb` captures
  per-role trace logs; `RUST_LOG=wt_hop_stats=trace` on `relay_bench` directly
  logs the relay hop's per-connection QUIC stats.

### Comparing the tuned vs default WebTransport hop

The WebTransport relay hop's QUIC config -- the tuning this branch adds (BBR +
reorder-tolerant loss detection) versus the noq defaults (Cubic, RFC 9002
reordering thresholds) -- is a single shared function
(`iroh_relay::protos::h3_streams::configure_relay_h3_transport`) toggled at
runtime with the `IROH_RELAY_H3_DEFAULT_TRANSPORT` env var. The driver drives
both from one sweep:

```bash
# each wt-* framing under both configs, per condition/mode; ws runs once
bench/run_relaybench.py --framings ws,wt-uni,wt-singlestream \
  --degradations wifi,4g,3g --modes download --configs tuned,default \
  --duration 10 --runs 3 --csv bench/results/ab.csv
# (auto-renders bench/results/ab-download.png)

# everything: all framings x all degradations x all modes x {tuned,default},
# rendering a grouped chart per mode. Long -- tune --runs / --duration.
bench/run_relaybench.py --full-matrix --duration 8 --runs 2 \
  --csv bench/results/full-matrix.csv
```

With more than one `--config`, the CSV gains a `config` column and each `wt-*`
framing gets **two bars** in the chart -- tuned (solid) and default (hatched),
with the tuned/default speedup labelled -- while `ws` (which does not use the
WebTransport hop) keeps a single bar. `plot_relaybench.py <csv> <png> --mode
<mode>` renders one mode; the driver renders each mode automatically for a
multi-config run.
- Output CSV columns: mean/min/max/stddev goodput plus `loss_pct`, `rtt_us`, and
  `tx_batch`/`rx_batch` (mean GSO/GRO batch on the tunneled p2p connection).

CSV/PNG outputs are git-ignored except the curated sets under `results/` (see
`.gitignore`).

## Secondary / legacy harnesses

- **In-test degraded rundown (`relay_degrade`).** A patchbay integration test
  (linux, rootless, serial) that sweeps the framings against `wifi`/`4g`/`3g`
  in-process. `bench/run_rundown.sh [RUNS]` runs the ladder N times and writes
  `results-raw.csv` / `results-agg.csv` / `rundown.png` (all git-ignored);
  `plot_rundown.py` renders it. A fast `relay_degrade_quick` variant exists for
  iteration. See `iroh/tests/patchbay/relay_degrade.rs`. Superseded for headline
  numbers by the real-process harness above, but useful as an independent
  cross-check.
- **Localhost loopback script (`bench/run.sh`).** The original harness: a
  `--dev-tls` relay plus a `provide`r/`fetch`er on loopback, prints per-run
  throughput and the transport used. Predates `--webtransport-only`, so its
  WebTransport runs relied on source patches to beat the WS race; use
  `--webtransport-only` instead. Kept for reference.
