# H3 relay throughput benchmark

Measures real end-to-end transfer goodput through a **localhost relay**,
comparing the three relay transports:

- **wss** -- relay client over WebSocket-Secure (HTTP/1.1 upgrade, one stream).
- **wt-unistream** -- WebTransport, one fresh unidirectional QUIC stream per
  relay message (the default WebTransport framing).
- **wt-datagram** -- WebTransport, one QUIC datagram per relay message
  (experimental, built with `--cfg h3_datagrams`).

It drives the `transfer` example (a `provide`r and a `fetch`er) through a
`--dev-tls` relay and reports upload/download throughput and which transport was
actually used. Three directions are supported: `download`, `upload`, and `bidi`.

The binaries in this directory and the `results-*.txt` / `logs/` outputs are
git-ignored (see `.gitignore`); only the scripts and this README are committed.

## What you need

- A release checkout of this branch.
- Ports 8443 (relay HTTPS/H3) free on loopback.
- Enough time: each cell is `RUNS` runs of `DURATION` seconds plus ~5s setup.

## Build the binaries

The runner expects five release binaries in this directory. The `transfer`
example needs the `test-utils` feature for `--relay-only`. `CARGO_TARGET_DIR`
below assumes the common `~/rust_target`; adjust to your target dir.

```bash
cd <repo root>
T=~/rust_target/release   # your cargo target dir + /release

# Relay, default features -- serves both WSS and uni-stream WebTransport.
cargo build --release -p iroh-relay --features server --bin iroh-relay
cp "$T/iroh-relay" bench/iroh-relay-h3

# Relay, datagram framing.
RUSTFLAGS="--cfg h3_datagrams" \
  cargo build --release -p iroh-relay --features server --bin iroh-relay
cp "$T/iroh-relay" bench/iroh-relay-dgram

# Transfer client without h3-transport -- can only use WSS.
cargo build --release -p iroh --no-default-features \
  --features test-utils,tls-ring --example transfer
cp "$T/examples/transfer" bench/transfer-wss

# Transfer client, default features (uni-stream WT) + the WT-forcing patches
# below applied to the source.
cargo build --release -p iroh --features test-utils --example transfer
cp "$T/examples/transfer" bench/transfer-uni

# Transfer client, datagram WT + the same WT-forcing patches.
RUSTFLAGS="--cfg h3_datagrams" \
  cargo build --release -p iroh --features test-utils --example transfer
cp "$T/examples/transfer" bench/transfer-dgram

# Revert the WT-forcing patches afterwards -- they must never be committed.
```

### WT-forcing patches (localhost only)

Against a **localhost, self-signed** relay the transfer client will not pick
WebTransport on its own, so `transfer-uni` and `transfer-dgram` must be built
from a patched tree. Two independent reasons, three small edits:

1. The client only uses WebTransport when `h3_enabled && udp_available`.
   `udp_available` is set from net_report's QAD probe, which fails against the
   relay's self-signed cert (the probe has no `--insecure`), so it stays
   `false` and the client falls back to WSS. Force it `true` in
   `iroh/src/socket.rs`: the initial `AtomicBool::new(false)` (~line 926) and
   the store in `handle_net_report_report` (~line 1969).
2. `connect()` races WebTransport against WebSocket and keeps whichever
   connects first; on loopback the WS TCP connect wins. Make the WS side never
   resolve so WT wins the race, in `iroh-relay/src/client.rs` `connect_race`
   (~line 361): replace `let ws_fut = self.connect_ws();` with a future that
   never completes (e.g. `std::future::pending()`).

**None of this is needed against a real relay with a valid certificate:** the
QAD probe confirms UDP and the 1-RTT WebTransport handshake beats WSS on its
own, so a stock `transfer` build picks WebTransport automatically.

## Run

```bash
bench/run.sh [RUNS] [DURATION_SECS] [MODE]     # MODE = download | upload | bidi

bench/run.sh 3 10 download     # 3 runs, 10s each, download
bench/run.sh 3 10 upload
bench/run.sh 3 10 bidi
```

`run.sh` starts a `--dev-tls` relay, a `provide`r, and a `fetch`er
(`--relay-only --insecure --no-pkarr-publish --no-dns-resolve`, fixed
`IROH_SECRET`s), runs all three transports per iteration, and prints each run's
throughput plus the transport it used (`wt` if the relay logged a
`wt-relay-conn`, else `ws`). Per-run logs land in `bench/logs/`.

To drive one transport by hand:

```bash
# relay
bench/iroh-relay-h3 --dev-tls &
# provider (deterministic id from IROH_SECRET; read it from the log)
IROH_SECRET=0101...01 bench/transfer-uni provide \
  --relay-url https://localhost:8443 --relay-only --insecure \
  --no-pkarr-publish --no-dns-resolve
# fetcher
IROH_SECRET=0202...02 bench/transfer-uni fetch <PROVIDER_ID> \
  --mode download --duration 10 \
  --remote-relay-url https://localhost:8443 --relay-url https://localhost:8443 \
  --relay-only --insecure --no-pkarr-publish --no-dns-resolve
```

## Interpreting the results

Unidirectional (`download` / `upload`) is the meaningful comparison. On
loopback, datagram framing is fastest (it pays no per-message stream setup and
iroh's own QUIC connection running over the relay retransmits any dropped
datagram), uni-stream and WSS are a wash and direction-dependent. Rough
loopback numbers (release, 10s runs):

| direction | wss        | wt uni-stream | wt datagram |
| --------- | ---------- | ------------- | ----------- |
| download  | ~155 MiB/s | ~162 MiB/s    | ~219 MiB/s  |
| upload    | ~161 MiB/s | ~136 MiB/s    | ~232 MiB/s  |

Two important caveats:

- The datagram win **does not generalize off loopback.** A WebTransport
  datagram is capped at the relay connection's path MTU (~1400 on a real
  network vs 65536 on loopback), so a full relayed packet plus its framing must
  fit that budget. The relay H3 connection pins its minimum MTU to 1280 (see
  `iroh_relay`'s `H3_MIN_MTU`) so a minimum-size iroh packet always fits and
  datagram framing works on any real path; but the per-message budget is far
  smaller than on loopback, so the large loopback lead shrinks to a modest one.
  The `relay_degrade` rundown below measures the real off-loopback behaviour.
- `bidi` is not just noisy but pathological on a single relay path: the two
  directions fight over the relay's per-client queues, the datagram download
  collapses to a few MiB/s (datagrams dropped once the queue is full, then
  retransmitted over a congested path), uni-stream goes lopsided, and WSS is
  unstable. Treat `bidi` numbers as illustrative of that contention, not as a
  transport ranking.

## Degraded-network rundown (`relay_degrade`)

The loopback harness above measures peak goodput. To measure the transports
under realistic last-mile conditions there is a separate patchbay integration
test, `relay_degrade` (linux-only, rootless user namespaces, serial). It runs
two iroh endpoints behind symmetric `Nat::Corporate` NATs (so the connection
stays relay-only with IP transports and GSO enabled) over a single relay at a
1400-byte link MTU, sweeping the four framings (`ws`, `wt-uni`, `wt-datagram`,
and `wt-singlestream` -- a single ordered uni stream per direction, TCP-like)
against three realistic conditions (`wifi` / `4g` / `3g`) in all three
directions, plus a constant-rate datagram-delivery workload. See the module docs
in `iroh/tests/patchbay/relay_degrade.rs` for the topology and measurement
details.

```bash
bench/run_rundown.sh [RUNS]     # RUNS defaults to 3
```

It builds the test binary once, runs the full ladder `RUNS` times without
recompiling, and writes three artifacts under `bench/`: `results-raw.csv` (every
`RUNDOWN` row from every run), `results-agg.csv` (avg/min/max/stddev per cell),
and `rundown.png` (one panel per direction plus datagram delivery, one line per
framing, plotting the average with a min..max band). All three are git-ignored.

For fast iteration there is also `relay_degrade_quick` (all framings against
wifi and 3g, download only, at two small transfer sizes; finishes in a couple of
minutes), run directly:

```bash
cargo test --release -p iroh --test patchbay relay_degrade_quick \
  -- --ignored --test-threads=1 --nocapture 2>&1 | grep RUNDOWN
```

## Real-process harness: `run_relaybench.py` + `relay_bench`

The localhost script above and the in-test `relay_degrade` ladder both run the
transport inside a single test process. `iroh/examples/relay_bench.rs` instead
runs the release `transfer` example as a **real OS process in its own network
namespace** (via patchbay), over an in-process relay, so the measurement has no
in-process harness as a variable and supports long duration-based steady-state
runs. Linux only (patchbay uses unprivileged user namespaces; no sudo).

`bench/run_relaybench.py` drives it: a strictly sequential sweep over
framing x link-condition x direction, N runs per cell, into a CSV with mean
throughput plus the tunneled p2p connection's send/recv batch ratio, loss, and
RTT. Keep the machine otherwise idle -- the WT relay connect races a
timing-sensitive QUIC handshake that gets flaky under CPU contention.

```bash
cargo build --release -p iroh --features test-utils --example transfer --example relay_bench
bench/run_relaybench.py --framings ws,wt-uni,wt-singlestream,wt-datagram \
  --degradations wifi,4g --modes download --duration 8 --runs 3
# per-role trace logs: add --rust-log 'iroh_relay=debug' --log-dir /tmp/rb
# relay-hop QUIC stats: RUST_LOG=wt_hop_stats=trace on relay_bench directly
```

Framings are the `transfer --relay-transport` values (`ws`, `wt-uni`,
`wt-datagram`, `wt-singlestream`). `--duration` gives steady-state goodput;
`--size` gives a fixed-size transfer. Output CSV columns include `tx_batch` /
`rx_batch` (mean GSO/GRO batch on the p2p connection), `loss_pct`, and `rtt_us`.
