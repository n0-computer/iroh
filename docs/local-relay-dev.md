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

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|--------------|-----------|
| `certificate unknown` / TLS handshake failure in relay log | Missing or incorrect Subject Alternative Name (SAN) on self-signed cert | Regenerate cert with `-addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"` and restart relay |
| Client hangs before QAD probes appear | Relay not started with `enable_quic_addr_discovery = true` or wrong config path | Verify relay startup args and that config file path is correct |
| `address already in use` on relay start | Another process occupying port 7842/3340/9090 | Stop conflicting process or edit config to use alternate ports |
| No `quic` / `net_report` trace lines despite RUST_LOG set | Shell quoting dropped part of RUST_LOG value | Echo `echo $RUST_LOG` to confirm; wrap the entire value in single quotes |
| Relay logs show QAD probes but transfer example fails to connect | Client used stale endpoint ID or omitted `--relay-only` flag causing mixed path attempts | Re-run provider, copy fresh ID, ensure both sides use consistent flags |
| `unsupported certificate version` error earlier | Initial cert generated without SAN extension | Use updated openssl command with SANs (see cert generation section) |
| Connect-unreliable example prints `No addresses tried` | Missing or malformed `--addrs` value | Provide space-separated address list quoted as one argument |
| Slow or no datagram exchange | Local firewall or nftables blocking UDP | Temporarily disable or add allow rules for UDP 7842 and dynamic client ports |

### Quick Verification Script
After generating certs & configs (see helper script), you can verify relay ports:

```
ss -tulpn | grep -E '(:3340|:7842|:9090)'
```

### Increasing Detail
Add `quinn=trace` and `rustls=trace` to RUST_LOG for deep debugging, but expect very verbose output.

### Filing Issues
When filing an issue about local relay/QAD, include:
- Relay command line & config snippet
- `RUST_LOG` value
- Snippets of relay and client logs around the failure
- Output of `openssl x509 -in tmp/certs/cert.pem -noout -text | grep -i subjectaltname -A1`

See `scripts/local-relay-setup.sh` (added in follow-up PR) for automated setup.
