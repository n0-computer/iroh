# Relay WebTransport vs WebSocket Benchmark

## Setup

- **Platform**: Linux 6.18.13-arch1-1, Rust release mode
- **Relay**: `iroh-relay --dev-tls` (self-signed certs, HTTPS + WT on port 8443)
- **Client**: transfer example with `--relay-only --insecure`
- **Duration**: 10 seconds

## Results (localhost, release mode)

### WebTransport over QUIC

```
Size:       1305.6 MB
Duration:   10.01s
Throughput: 130.4 MB/s (1043 Mbit/s)
TTFB:       8.1ms
Chunks:     300,778
```

### WebSocket over HTTP/1.1 (previous measurement, same hardware)

```
Size:       1308.6 MB
Duration:   10.01s
Throughput: 130.7 MB/s (1046 Mbit/s)
TTFB:       4.9ms
Chunks:     343,922
```

### Comparison

On localhost, throughput is virtually identical (~1 Gbit/s). TTFB is slightly
higher for WT due to the WebTransport settings exchange + CONNECT handshake on
top of the QUIC handshake. This overhead disappears at real-world RTTs where the
QUIC handshake is the dominant cost.

## RTT analysis

### WebTransport path (1 RTT to first relay byte)

```
Flight 1 (client -> server):
  QUIC ClientHello
  + Client Settings (uni stream, pipelined per RFC 9114 7.2.4.2)
  + CONNECT request with keying material auth header (bidi stream)

Flight 2 (server -> client):
  QUIC ServerHello + handshake
  + Server Settings (uni stream)
  + CONNECT 200 response
  + WT data bidi stream (Frame::WEBTRANSPORT header)
  + ServerConfirmsAuth (keying material verified from CONNECT header)

Total: 1 RTT (QUIC handshake carries everything)
```

### WebSocket path (3-4 RTTs)

```
RTT 1: TCP SYN/SYN-ACK
RTT 2: TLS ClientHello/ServerHello
RTT 3: HTTP Upgrade to WebSocket
RTT 4: Relay challenge-response (0 if TLS keying material available)
```

### Improvement summary

| | WebTransport | WebSocket | Savings |
|---|---|---|---|
| First connection | 1 RTT | 3-4 RTTs | 2-3 RTTs |
| With keying material | 1 RTT | 3 RTTs | 2 RTTs |
| At 100ms RTT | ~100ms | ~300-400ms | 200-300ms |

### 0-RTT considerations

The WebTransport spec prohibits CONNECT in 0-RTT packets (CONNECT is not
idempotent). QUIC 0-RTT could carry the client Settings, but the CONNECT must
wait for the 1-RTT keys. No further RTT savings are possible within the spec.

## How to reproduce

```sh
# Terminal 1: relay server
cargo run --bin iroh-relay -p iroh-relay --features server --release -- --dev-tls

# Terminal 2: provider
cargo run --example transfer -p iroh --features test-utils --release -- \
  provide --relay-url https://localhost:8443 --relay-only --insecure

# Terminal 3: fetch
cargo run --example transfer -p iroh --features test-utils --release -- \
  fetch ENDPOINT_ID --relay-url https://localhost:8443 \
  --remote-relay-url https://localhost:8443 \
  --no-address-lookup --relay-only --insecure --duration 10
```
