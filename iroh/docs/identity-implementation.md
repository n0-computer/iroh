# Pluggable identity implementation

The native `unstable-identity` feature demonstrates pluggable authentication with
Ed25519 and ML-DSA-65. Key exchange is outside this work. Independent security
review and production release approval remain subsequent gates.

## Implemented behavior

- Normal `Endpoint::builder(Empty).credentials(identity, registry)` integration,
  with explicit `remote_policy` for signature suites and optional exact peer IDs.
- Full typed peer IDs through direct and relay routing; no surrogate Ed25519 key.
- Mutual raw-public-key TLS authentication over direct IP and versioned relays.
- Authenticated QUIC NAT traversal, direct-path selection and relay backup.
- Unchanged legacy Ed25519 encodings and bidirectional released-version interop.
- Exportable built-in keys, non-exportable custom signers, and persistent explicit
  application trust migration with compare-and-replace semantics.
- Bounded relay queues, registration policy, reconnects and exact identity pinning
  throughout. Transport retries do not change the requested identity or algorithm.
- Expiring unverified routes, protected connection routes and reserved dial capacity;
  shared source quotas for typed relay registration and forwarding.

## API

```rust,no_run
use std::sync::Arc;
use iroh::{Endpoint, endpoint::presets::Empty};
use iroh::identity::{LocalIdentity, Registry, RemotePolicy};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let registry = Arc::new(Registry::builtins(vec![1, 2])?);
let credential = LocalIdentity::generate_ml_dsa65(&registry)?;
let endpoint = Endpoint::builder(Empty)
    .credentials(credential, registry)
    .remote_policy(RemotePolicy::new([2]))
    .bind_addr("127.0.0.1:0".parse()?)
    .alpns(vec![b"example/1".to_vec()])
    .bind().await?;
endpoint.close().await;
# Ok(()) }
```

`credentials` is an explicit type transition: its builder returns
`identity::IdentityEndpoint`, whose connection and address types carry `PeerId`.
Existing `.secret_key(...)` callers retain their existing types and behavior.
Each endpoint presents one credential; deployments can run both endpoint types.
A legacy credential accepting only PQ peers is also supported, independently of
which local adapter is installed. This does not make the legacy signature PQ.

For relays, enable the feature in `iroh-relay` and explicitly call
`server.relay_service().unwrap().enable_identity(Service::new(url, registry, limit))`.
This adds `/relay/identity-v1` with WebSocket subprotocol `iroh-identity-relay/1`.
The registry controls typed registration independently of legacy relay access
control. Existing `/relay` is unchanged. Both versions can share one HTTP server.
New registration uses a fresh random challenge, the canonical relay URL, and the
complete peer ID. The server supplies each forwarded packet's authenticated source.

Configure a custom `RelayMap` on the endpoint. Its QAD configuration supplies the
existing QUIC address-discovery port. Supply peer addresses directly with
`EndpointAddr::new(peer_id, socket_addr)` or `EndpointAddr::relay(peer_id, relay_url)`.
TLS independently verifies the requested identity. Signed-contact lookup and
publication are deferred to a separate contribution.

### Admission limits

The typed routing table holds at most 4096 routes, with 64 slots reserved for
locally initiated dials. Unverified routes become reclaimable after 30 seconds;
packet traffic does not renew them. Accepted handshakes, local dials and established
connections hold peer route leases. After the last lease is released, routes get
a 30-second drain grace period. New routes use fresh synthetic addresses even
after reclamation. Expiry scans occur only under pressure, at most once per second.
Packets for a reclaimed synthetic address are dropped, never written to a socket.

A relay session that proves its credential replaces any earlier session for the
same identity, so a peer whose connection died silently can register again. Both
ends ping idle sessions every 15 seconds and drop a peer silent for 45 seconds.
The relay reserves a session slot before answering an upgrade, returning 503 at
capacity. Endpoints accept incoming handshakes concurrently, up to 1024 at once,
and refuse further attempts, so a stalled handshake cannot block other peers.

Typed relay upgrades and sessions share canonical TCP-source-IP limits: 120
admissions per 60-second window and 16 concurrent sessions. Relay ingress is limited to
64 MiB and 32,768 frames per source per one-second window, shared across sessions
and reconnects. Excess HTTP admission returns 429; excess relay traffic disconnects
the session. These are fixed-window feasibility defaults. Shared NAT users share
limits; distributed sources and IPv6 address rotation require additional controls.

Source accounting holds at most 4096 entries, reclaiming inactive expired entries
under pressure. Embedders using `RelayServiceWithNotify` must supply the actual
TCP source with `with_source_ip`; otherwise all such connections share an unknown
source quota. Forwarding headers are never trusted. The normal server supplies
the TCP peer address automatically. Legacy protocol limits remain independent.

Persist built-in credentials with `LocalIdentity::save/load`. The file is created
exclusively, with Unix mode 0600; `to_bytes/from_bytes` support other storage.
`SecretBytes` zeroizes its buffer and redacts Debug output. Custom signers need not
export keys. `TrustStore::trust`, `migrate`, `revoke`, `save` and `load` give applications
explicit pin management. Approve a replacement through an application-trusted
channel before calling `migrate(name, old, approved_new)`. Address reuse
and successful authentication cannot migrate pins or copy permissions.

## Testing

See the [identity test guide](../tests/identity/README.md) for the ordinary suite,
released-version interoperability, and Linux NAT traversal commands.

## Packaging

Release `iroh-base`, then `iroh-identity`, then `iroh-relay`, then `iroh`. The optional
identity dependency must be published even for consumers that disable the feature.
To check the dependency chain before publication:

```sh
cargo package -p iroh-base -p iroh-identity -p iroh-relay -p iroh --allow-dirty --no-verify --offline
```

## Limitations

- Native experimental API and protocol assignments; no browser/Wasm support or
  production security approval. Independent review must cover the new protocol,
  canonical encodings, adapter trust, resource limits and implementation.
- Relayed PQ connections require upgraded, explicitly enabled relays.
  Legacy pkarr/DNS records and legacy relay routing cannot encode a PQ identity.
  Existing public relay infrastructure is not upgraded by enabling this feature.
- Legacy discovery services, endpoint hooks, HTTP proxies, custom transports,
  `secret_key`, `dns_resolver`, `addr_filter`, lookup user data and
  `max_tls_tickets` are rejected by the credentials transition instead of being
  dropped. Use `Empty`, supply peer addresses, and select compatible relays.
  Full parity with all legacy builder options is outside this feasibility
  implementation.
- Binding performs no network I/O. Configured relays connect in the background
  with backoff, so an unreachable relay delays relayed reachability only.
- Local interfaces are enumerated at bind. QAD refreshes observed mappings on top
  of that base set, so a failed probe never withdraws an interface address. Full
  network-monitor rebinding, portmapper integration, relay selection and every
  NAT/roaming combination still need broader integration work.
- Relay registration is bounded by the configured session capacity, queues hold
  256 datagrams with nonblocking drop on congestion, and endpoint routing is
  capped at 4096 peer/relay pairs. Relays joined for a dial hint are capped at
  16; one with no pinned routes for a minute, or unreachable for about two
  minutes, is left and its routes are forgotten, and the least recently joined
  idle one is evicted when the cap is reached. The service's legacy traffic
  rate-limit configuration does not govern the typed protocol;
  deployment-specific rate limits and abuse controls need review.
- Key files are unencrypted. Protect their parent directory and storage medium.
  Trust-store replacement is atomic, but callers coordinate concurrent writers.
  Unix permission checks do not establish an equivalent Windows ACL policy.
- Resumption and early data remain disabled. Algorithms are registered trusted
  code; registry checks cannot establish a custom adapter's cryptographic quality.
  PQ authentication alone does not establish PQ confidentiality or a full-system
  security level. No key-exchange migration is included.
