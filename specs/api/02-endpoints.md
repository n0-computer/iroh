# Endpoints

**Version:** 1.0

An iroh endpoint is the central object that manages peer-to-peer connectivity. It combines a cryptographic identity with network services — relay connections, address discovery, and hole punching — to establish and maintain QUIC connections with other endpoints.

## Endpoint ID

An endpoint's identity is its Ed25519 public key, called the **Endpoint ID**. This is a 32-byte value that uniquely identifies the endpoint across the network. The corresponding secret key is held privately and never transmitted.

The Endpoint ID serves three roles:
- **Identity**: It is the stable, globally unique identifier for the endpoint.
- **Authentication**: During TLS handshake, each side proves possession of their secret key and verifies the peer's Endpoint ID.
- **Addressing**: It is used as a lookup key for address discovery (see [Address Lookup](05-address-lookup.md)) and as a routing key by relay servers.

## Endpoint Setup

When an endpoint starts up, it performs several initialization steps to become reachable on the network.

### Key Generation

If no secret key is provided, the endpoint generates a new Ed25519 key pair. The public key becomes the Endpoint ID. If a secret key is provided, the endpoint uses it directly, allowing a stable identity across restarts.

### Home Relay Selection

The endpoint connects to relay servers to ensure it is always reachable by other endpoints. On startup, it performs latency probes to all configured relay servers to determine which one to use as its **home relay**:

1. The endpoint sends probes to each configured relay server. Three probe types are used: HTTPS latency, QAD over IPv4, and QAD over IPv6.
2. For each relay, the minimum latency across all successful probe types is recorded.
3. The relay with the lowest minimum latency is selected as the home relay.
4. The endpoint establishes a persistent connection to its home relay.

The home relay is the primary rendezvous point where other endpoints will reach this endpoint. It is advertised as part of the endpoint's addressing information (see [Addressing](04-addressing.md)) and published via address lookup services (see [Address Lookup](05-address-lookup.md)).

If network conditions change — for example, the endpoint moves to a different network — the endpoint re-runs latency probes and may switch to a different home relay.

### Address Publication

Once the home relay is selected, the endpoint publishes its addressing information so that remote endpoints can find it. This typically includes the home relay URL and, depending on configuration, direct IP addresses. See [Address Lookup](05-address-lookup.md) for details on the publication mechanism.

### Accepting Connections

To accept incoming connections, the endpoint must be configured with one or more ALPN protocol identifiers. These declare which application protocols the endpoint supports. Without ALPNs configured, the endpoint can initiate connections but cannot accept them.

## TLS Authentication

Iroh uses TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) with **Raw Public Keys** ([RFC 7250](https://www.rfc-editor.org/rfc/rfc7250)) instead of X.509 certificate chains. Each endpoint presents its Ed25519 public key directly as a raw public key in the TLS handshake.

Authentication is **mutual**: both sides of a connection present and verify public keys. The initiating side verifies that the peer's public key matches the expected Endpoint ID. The accepting side authenticates the peer's identity through signature verification during the TLS handshake, then decides at the application level whether to allow the connection.

### Server Name Indication

To identify the intended peer during TLS handshake, iroh encodes the target Endpoint ID in the TLS Server Name Indication (SNI) field using the format:

```
{BASE32-DNSSEC(endpoint_id)}.iroh.invalid
```

The `.iroh.invalid` suffix uses a reserved TLD to ensure these names never collide with real DNS names. The BASE32-DNSSEC encoding follows [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648).

### Session Resumption and 0-RTT

Iroh supports TLS session resumption and 0-RTT connection establishment. When an endpoint has previously connected to a peer, it can cache a session ticket and use it to resume the connection with reduced latency, sending application data in the first flight of packets.
