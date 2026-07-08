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
  datagram is capped at the QUIC path MTU (~1400 on a real network vs 65536 on
  loopback), smaller than a full relayed packet plus its framing, so those
  messages would be rejected by `send_datagram`. Datagram framing is only
  viable for small messages or large-MTU paths.
- `bidi` is not just noisy but pathological on a single relay path: the two
  directions fight over the relay's per-client queues, the datagram download
  collapses to a few MiB/s (datagrams dropped once the queue is full, then
  retransmitted over a congested path), uni-stream goes lopsided, and WSS is
  unstable. Treat `bidi` numbers as illustrative of that contention, not as a
  transport ranking.
