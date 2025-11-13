# Local relay development and QAD validation

This document describes how to run a local iroh-relay with QUIC Address Discovery (QAD), point clients at it by default, and validate connectivity with examples.

## Summary
- Relay HTTP: 3340 (dev mode)
- Relay metrics: 9090
- Relay QUIC (QAD): UDP 7842
- Local config file: `iroh.config.toml` (ignored by git) with the local relay URL
- Relay config: `tmp/iroh-relay.config.toml` (not tracked) enabling QAD with TLS
- Logs: `tmp/relay.log`, `tmp/transfer-*.log`, `tmp/listen-unrel.log`, `tmp/connect-unrel.log`

## Generate a self-signed TLS cert with SAN (required by rustls)

```
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout tmp/certs/cert.key.pem -out tmp/certs/cert.pem \
  -days 365 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
```

## Relay config enabling QUIC Address Discovery
Create `tmp/iroh-relay.config.toml`:

```toml
# enable QUIC address discovery and manual TLS
enable_quic_addr_discovery = true

[tls]
cert_path = "tmp/certs/cert.pem"
key_path  = "tmp/certs/cert.key.pem"
```

## Prefer the local relay by default (client)
Create `iroh.config.toml` at the repo root (git-ignored):

```toml
[[relays]]
url = "http://localhost:3340"
```

## Run the relay with verbose logs

```
RUST_LOG='info,iroh_relay=debug,iroh_relay::quic=trace,iroh::net_report=trace,quinn=info,rustls=info' \
  target/debug/iroh-relay --config-path tmp/iroh-relay.config.toml --dev 2>&1 | tee tmp/relay.log
```

## Smoke test: transfer (relay-only)
- Provider (relay-only):
```
cargo run -p iroh --example transfer --no-default-features --features test-utils -- \
  provide --env dev --no-pkarr-publish --no-dns-resolve --relay-only | tee tmp/transfer-provide.log
```
- Fetch (relay-only), replace <REMOTE_ID> with provider’s printed id:
```
RUST_LOG=iroh::net_report=trace \
cargo run -p iroh --example transfer --no-default-features --features test-utils -- \
  fetch <REMOTE_ID> --remote-relay-url http://localhost:3340 \
  --env dev --no-pkarr-publish --no-dns-resolve --relay-only | tee tmp/transfer-fetch.log
```
- Expect: connection established over relay; client logs show QAD probes and discovered relay address; relay log shows QAD connections established.

## Unreliable examples with local relay
- Listener (background):
```
cargo run -p iroh --example listen-unreliable | tee tmp/listen-unrel.log
```
- Connector (replace with listener’s ID and addrs):
```
cargo run -p iroh --example connect-unreliable -- \
  --endpoint-id <LISTENER_ID> \
  --addrs "<IP1:PORT> <IP2:PORT> ..." \
  --relay-url http://localhost:3340 | tee tmp/connect-unrel.log
```
- Expect: successful datagram exchange.

## Notes
- `iroh.config.toml` is in `.gitignore` to keep local relay preference local; `tmp/` is also ignored.
- QAD defaults to UDP port 7842 (see `iroh-relay/src/defaults.rs`).
- If a relay-only transfer fails, check `tmp/relay.log` for QUIC server bind and connection logs, verify cert SANs, and ensure ports are reachable.
