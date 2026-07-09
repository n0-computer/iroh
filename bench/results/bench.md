# Relay throughput benchmark: WebSocket vs WebTransport

Goodput of the iroh `transfer` example relayed through a single relay, comparing
the WebSocket relay transport against the three WebTransport (H3/QUIC) framings,
across a range of last-mile link conditions.

This directory holds saved result sets (CSV + PNG); the harness and driver that
produce them live one level up (`../relay_bench` example, `../run_relaybench.py`,
`../plot_relaybench.py`).

## What is measured

The fetcher downloads from the provider; both reach each other only through the
relay (they sit behind symmetric NATs, so no direct path exists). "Goodput" is
the application bytes transferred divided by the transfer wall time, reported in
Mbit/s. Each connection is a full iroh QUIC connection tunneled over the relay
transport, so the numbers reflect an already-congestion-controlled connection
carried over a second transport (TCP for `ws`, QUIC/WebTransport for `wt-*`).

## Transports (`--relay-transport`)

- **ws** -- WebSocket over TCP (HTTP/1.1 upgrade). One ordered reliable stream.
- **wt-uni** -- WebTransport, one fresh unidirectional QUIC stream per relayed
  message.
- **wt-singlestream** -- WebTransport, one long-lived ordered unidirectional
  stream per direction (TCP-like, over QUIC).
- **wt-datagram** -- WebTransport, one QUIC datagram per relayed message
  (unreliable; capped at the connection's max datagram size).

## Harness

`relay_bench` (linux only) builds a patchbay network -- one public backbone
router, a relay device, and two peers each behind their own Corporate
(symmetric) NAT -- using unprivileged user namespaces (rootless, no sudo). The
relay runs in-process in the relay device's namespace; the provider and fetcher
run as the release-built `transfer` example as real OS processes in each peer's
namespace. Link impairment is applied to both peers' access links in both
directions via `tc netem` (+ `tc tbf` when a rate cap is set).

`run_relaybench.py` drives a strictly sequential sweep (nothing else running:
the numbers are throughput and any competing load skews them, and the WT connect
races a timing-sensitive QUIC handshake that flakes under CPU contention). It
writes an aggregated CSV (mean/min/max/stddev per cell, plus the tunneled
connection's loss, RTT, and send/receive batch counters).

### Link conditions (`--degradation`)

netem parameters applied to each peer's access link (both directions):

| condition | latency | jitter | loss  | rate cap |
| --------- | ------- | ------ | ----- | -------- |
| lan       | 0       | 0      | 0     | none     |
| wifi      | 5 ms    | 2 ms   | 0.1 % | none     |
| 4g        | 25 ms   | 8 ms   | 0.5 % | none     |
| 3g        | 100 ms  | 30 ms  | 2 %   | 2 Mbit   |

Link MTU is 1400 for every link. Note the two access links compose, so the
end-to-end (peer <-> relay <-> peer) path sees roughly twice the one-way latency
and the loss/jitter of both hops.

### localhost baseline

The `localhost` result set runs relay + provider + fetcher as plain loopback
processes on `127.0.0.1` with no patchbay namespaces, veth, NAT, or netem at all
-- a control for the harness's own overhead and an upper bound for each
transport on an ideal path.

## Result sets

Two 3-run, 10s steady-state sweeps that differ only in the WebTransport relay
hop's QUIC transport config (a single shared knob,
`iroh_relay::protos::h3_streams::configure_relay_h3_transport`, toggled with the
`IROH_RELAY_H3_DEFAULT_TRANSPORT` env var):

| file | WebTransport hop config | notes |
| ---- | ----------------------- | ----- |
| `wt-tuned-3x10s`   | BBR + reorder-tolerant loss detection (the fix) | the authoritative result |
| `wt-default-3x10s` | default congestion control (Cubic), RFC 9002 reordering thresholds (baseline) | shows what the tuning buys |

Both force the WebTransport transport for every `wt-*` run
(`--webtransport-only`), so those numbers are guaranteed WebTransport and never a
silent WebSocket fallback. That fallback matters: the relay client races a
WebSocket connect against the WebTransport handshake and keeps whichever wins,
and on a fast path (localhost, often lan) the WebSocket TCP handshake wins, so
without forcing it a `wt-*` request is served over WebSocket. `ws` is identical
in both sets (it does not use the WebTransport hop); its cross-set differences
are pure run-to-run variance (largest on the fast paths).

### `wt-tuned` numbers (download goodput, Mbit/s, mean of 3)

| condition | ws | wt-uni | wt-singlestream | wt-datagram |
| --------- | -- | ------ | --------------- | ----------- |
| localhost | 890 | 1004 | 1141 | **1892** |
| lan       | **2780** | 1580 | 1993 | 1903 |
| wifi      | 179 | 125 | 134 (0.75x) | 17 |
| 4g        | 4.0 | **25.2** (6.2x) | 22.5 (5.6x) | 2.0 |
| 3g        | 0.47 | 0.86 (1.8x) | **1.08** (2.3x) | fail (see note) |

### What the tuning buys (`wt-tuned` vs `wt-default`, wt goodput Mbit/s)

| condition | framing | default | tuned | gain |
| --------- | ------- | ------- | ----- | ---- |
| wifi | wt-uni | 30.8 | 125 | **4.1x** |
| wifi | wt-singlestream | 38.7 | 134 | **3.5x** |
| 4g   | wt-uni | 2.9 | 25.2 | **8.7x** |
| 4g   | wt-singlestream | 3.8 | 22.5 | **5.9x** |
| 3g   | wt-uni | fails 0/3 | 0.86 | works at all |
| 3g   | wt-singlestream | 0.32 | 1.08 | **3.4x** |
| localhost | wt-singlestream | 1393 | 1141 | 0.82x (BBR costs a little) |
| lan  | wt-singlestream | 2661 | 1993 | 0.75x (BBR costs a little) |

The tuning is transformative on the lossy/jittery links it targets (3.5-8.7x,
and it makes wt-uni work on 3g at all) because the default loss-based Cubic
overruns the shallow-buffer link and QUIC misreads the jitter as loss (the
reliable relay stream then retransmits ~40%). On clean, fast paths
(localhost/lan) BBR slightly under-utilises versus Cubic, so the default is a bit
faster there -- but those cells are also the noisiest run to run (e.g. `ws`
localhost swung 890 vs 1370 across the two sets), so the small clean-path
difference is not conclusive; the large impaired-link gains are.

Reading it: on an ideal path (localhost, huge MTU, no loss) the unreliable
datagram framing is fastest and the streams sit around WebSocket; on a clean
gigabit LAN WebSocket's single kernel-TCP stream wins (WebTransport pays
double-QUIC overhead); on wifi ws and the WebTransport streams are comparable
(within the fairly wide wifi run-to-run spread); from 4g down the reorder/loss
tolerance of the tuned WebTransport hop dominates -- ~6x on 4g (where TCP
loss-collapses, see the 4g section below) and ~2x on 3g. `wt-datagram` is strong
only on large-MTU paths and degrades to unusable on the constrained mobile
profiles; on 3g it fails all runs because forcing WebTransport removes the
WebSocket fallback that otherwise masks its flaky connection setup there (see the
wt-datagram note).

Each `.png` is small multiples (one panel per condition, own linear scale since
goodput spans ~3 Gbit on LAN to ~0.5 Mbit on 3G); each bar shows its min..max
range, the average, and the ratio versus the `ws` baseline, with a min..max
whisker.

## Why WebSocket is slow on 4g (and WebTransport wins there)

Surprising at a glance: ws leads on lan/localhost but is ~5x slower than
WebTransport on 4g. It is the classic TCP-vs-QUIC/BBR loss story. The 4g profile
is 0.5% loss with no rate cap. The WebSocket relay hop is a TCP connection, and
TCP's loss-based congestion control backs off on every loss (its Mathis ceiling
at 0.5% loss is only single-digit Mbit) while keeping the bottleneck buffer full.
The tunneled iroh connection over it shows ~1.4-1.7 s RTT (pure bufferbloat) with
0.00% end-to-end loss -- delivered reliably but slowly. The WebTransport relay
hop is QUIC with BBR (paces to the bottleneck bandwidth, does not treat loss as
congestion) plus this branch's reorder-tolerant loss detection, so 0.5% loss and
8 ms jitter do not throttle it: ~0.28 s RTT, ~5x the throughput. Since the
tunneled connection is receive-window limited (~1 MB, same both ways),
throughput = window / RTT, so the ~5x RTT gap is the ~5x throughput gap. This
drives the whole crossover: loss-free lan -> ws wins; 0.1% wifi -> comparable;
0.5% 4g (no cap) -> WebTransport ~5x; 2 Mbit-capped 3g -> both low, WT ahead.

## wt-datagram note

`wt-datagram` is the weak framing and shows failures on 3G in the aggregated
runs, but the cause is NOT the datagram transport giving up. Traced: on 3G the
relay H3 connection settles at ~1293-byte MTU, so iroh's oversized MTU-discovery
probes (~1360 B) exceed the datagram budget (~1328 B) and are dropped -- but
`send_datagram` swallows `TooLarge` non-fatally and iroh's PLPMTUD backs the
packet size down within the first ~3 s (exactly ~6 dropped packets), after which
the transfer completes cleanly. Isolated 3G datagram runs succeed (slow,
~0.15 Mbps). The "failures" in the matrix are the WT connection SETUP flaking on
the harsh 3G link (100 ms latency, 30 ms jitter, 2 % loss) under back-to-back
load -- the same timing-sensitive H3/QUIC handshake flakiness that also affects
the stream framings, just most visible on the worst cell. It is a
connection-establishment issue, not a datagram-framing one.

## Headline finding

With reorder-tolerant loss detection (`packet_threshold` + `time_threshold`) and
BBR on the relay H3 hop (committed on `relay-h3-bench-perf`), WebTransport went
from 3-4x slower than WebSocket everywhere to: parity on wifi, several times
faster on the lossy/jittery mobile profiles (4g/3g), and ~80-85% on a clean LAN
(inherent double-QUIC overhead). See the per-set PNGs and the repo's
`plans/h3-debug.md` for the full analysis.
