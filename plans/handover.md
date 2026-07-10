# Handover: WebTransport relay throughput -> WebSocket parity

Worktree: `iroh-worktrees/relay-h3` (branch `relay-h3`). Companion repo:
`~/Code/rust/patchbay` (branch `feat/link-realism`).

## TL;DR

The WebTransport relay transport was ~2x slower than WebSocket on realistic
links. Root cause: the relay's H3/QUIC hop ran **BBR3**, whose bandwidth estimate
collapses on the tunnelled hop (the reliable tunnel looks app-limited whenever
the inner connection is flow-control blocked), pinning the hop congestion window
to ~85 KB and throttling goodput to ~half of ws. Fix: **remove the BBR3 line** so
the hop falls back to noq's default (Cubic) -- the same loss-based controller ws'
TCP hop uses -- keeping the already-present raised reorder thresholds, which are
the actual load-bearing tuning. Net functional diff vs the branch is one deleted
line. `wt-singlestream` now reaches ws parity (and beats it on 4g/localhost).

## Root cause (how it was found)

1. The tunnelled iroh connection is **flow-control limited** (noq default 1.25 MB
   stream window), so its goodput is exactly `window / RTT`. qlog of the inner
   connection showed cwnd growing to 13 MB unused, inflight pinned ~1.15 MB in
   both ws and wt -- the ONLY difference was RTT (ws 67ms, wt-BBR 140ms).
2. Added an iroh-relay `qlog` feature to capture the **hop** connection's own
   qlog. The BBR3 hop cwnd collapsed 1467 KB -> 85 KB at t~6s and stayed there
   (inflight ~= cwnd, so cwnd-limited, not app-limited). That is the throttle.
3. `IROH_RELAY_H3_CC=cubic` -> hop cwnd stable ~280 KB, goodput 131 Mbit = ws
   parity. Confirmed across wifi/4g/3g; BBR3 is the only one that collapses.

Ablation (wifi wt-singlestream): the two reorder thresholds together are the
whole win (41 -> 126 Mbit); neither alone suffices (packet-only 77, time-only
43). The window and CC-select knobs were NOT load-bearing and were removed.

## The fix (shipped, minimal)

`iroh-relay/src/protos/h3_streams.rs::configure_relay_h3_transport`, tuned path
is now exactly:
```rust
config.packet_threshold(WT_REORDER_PACKET_THRESHOLD);  // 1000  (noq default 3)
config.time_threshold(WT_REORDER_TIME_THRESHOLD);      // 2.0   (noq default 1.125)
```
`max_concurrent_uni_streams(100_000)` and `min_mtu/initial_mtu(1280)` remain --
they are baseline framing-enablement for the uni/datagram framings (applied even
in the `IROH_RELAY_H3_DEFAULT_TRANSPORT` baseline), not throughput tuning. CC is
left at noq's default Cubic. `IROH_RELAY_H3_DEFAULT_TRANSPORT=1` still reverts the
reorder thresholds to noq defaults for A/B benchmarking.

## Results (realistic model, download, median mbps @ rtt)

| link | ws | wt-singlestream (fix) | vs ws |
| ---- | -- | --------------------- | ----- |
| localhost | 1.3-1.5G | 1.6G | ~1.15x |
| lan | 2.9G | 2.3G | 0.8x (Gbit double-QUIC overhead) |
| wifi | ~125 | ~130 | parity |
| 4g | ~14 | ~18-21 | 1.3-1.5x |
| 3g | ~1.2 | ~1.1 | ~0.9x |

Symmetric on upload. Graphs/CSVs in `bench/results/overnight/`
(`realistic-matrix-4run-download.png` is the latest; full write-up in
`bench/results/overnight/claude-report.md`).

## Known remaining issues

1. **wt-singlestream is bimodal on deep-buffer/high-RTT links (4g especially).**
   Most runs match ws (~18-21 Mbit), but a fraction bufferbloat-collapse (RTT ->
   2.8s, goodput ~2 Mbit). The nested congestion control (inner iroh QUIC over
   the reliable hop) sometimes runs away. The 4 MB stream window that was removed
   damped this (8/8 tight vs ~1/8 collapsing); it was dropped for minimality. If
   4g stability matters, re-add a bounded hop stream window or otherwise cap
   nested inflight.
2. **wt-uni stays ~2x slower than ws** and is NOT fixed by the hop CC. Its
   per-message streams deliver the tunnelled iroh packets REORDERED, and the
   inner (app) connection's default reorder threshold (3) reads that as loss
   (~250 spurious retransmits). Inherent to per-message framing over an ordered
   QUIC tunnel.
3. **Default framing is `UniPerPacket` (wt-uni)** -- the slow one. `UniOrdered`
   (wt-singlestream) is the framing that reaches parity. Switching the client
   default to UniOrdered is recommended BUT wire-compat sensitive: "singleuni" is
   new in this branch and `WtTransferMode::from_query_value` falls back to
   `UniPerPacket`, so a new client against an older relay would framing-mismatch.
   Needs a negotiated-capability gate before flipping. Lever:
   `WtTransferMode`'s `#[default]` in `iroh-relay/src/relay_map.rs`, or the
   `H3Opts::transfer_mode` default.
4. **BBR3 cwnd collapse** on tunnelled/app-limited flows is arguably a noq bug
   worth reporting upstream.

## Benchmark harness

- `iroh/examples/relay_bench.rs`: patchbay lab, relay + two NAT'd peers, runs the
  release `transfer` example as a real process per peer namespace over an
  in-process relay. `--link-model {realistic(default),preset,capped,congestion}`,
  `--loss-burst N`, `--degradation`, `--localhost`, `--webtransport-only`.
- `bench/run_relaybench.py`: sequential sweep (framing x degradation x mode x
  {tuned,default}) -> CSV, auto-renders the grouped chart. `--configs
  tuned,default` toggles `IROH_RELAY_H3_DEFAULT_TRANSPORT`. `--link-model`,
  `--loss-burst` passthrough. Writes CSV incrementally.
- `bench/plot_relaybench.py`: small-multiples; whisker = min..max; tuned solid /
  default hatched.
- Ad-hoc sweep helper used during the investigation: `/tmp/qlog/sweep.sh RUNS
  FRAMING "label|ENV" ...` (median of N runs). qlog parser: `/tmp/qlog/analyze.py`.
- Rebuild BOTH examples after any iroh-relay change:
  `cargo build --release -p iroh --features test-utils --example transfer
  --example relay_bench`. `transfer` is the relay CLIENT.

## patchbay changes (branch `feat/link-realism`, 2 commits)

- `qdisc.rs`: `LinkLimits.buffer_ms` (RTT-sized tbf buffer -> congestion loss on
  overflow) and `loss_burst_pkts` (bursty Gilbert-Elliott loss instead of
  Bernoulli). Documented.
- `lab.rs`: reworked `LinkCondition` presets to measured 2024-2025 real-world
  figures (caps + RTT buffers + bursty loss).

The relay_bench `realistic` link model uses its OWN per-degradation params (in
`relay_bench.rs::Degradation::params`), not the patchbay presets directly, but it
needs the patchbay `buffer_ms`/`loss_burst_pkts` fields to compile -- hence the
dependency on the patchbay branch.

## Dependency note

The iroh workspace pulls patchbay from crates.io (`version = "0.6"`). To build the
bench against the patched patchbay it is overridden in the root `Cargo.toml`
`[patch.crates-io]`. See that file for the current form.
