# Connections

**Version:** 1.0

Iroh connections are QUIC connections as defined in [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), with iroh-specific TLS and transport configuration. This section describes the connection model from the application's perspective.

## Establishing a Connection

To connect to a remote endpoint, three pieces of information are needed:

1. **Endpoint ID** — the peer's Ed25519 public key (required)
2. **Addressing information** — a relay URL and/or direct IP addresses (optional if address lookup is configured)
3. **ALPN** — the application protocol identifier to negotiate

These are combined into an **Endpoint Address** (see [Addressing](04-addressing.md)).

When an endpoint initiates a connection, iroh proceeds as follows:

1. If no addressing information is provided, the configured address lookup service is queried to resolve the Endpoint ID to a relay URL and/or direct addresses.
2. A QUIC connection is initiated simultaneously on all available paths — direct IP addresses, relay server, and any custom transports.
3. The TLS handshake authenticates both peers using their Ed25519 keys (see [Endpoints](02-endpoints.md)).
4. The fastest path to complete the handshake is used. If the relay path wins, iroh begins hole punching to establish a direct connection in the background (see [Holepunching](07-holepunching.md)).
5. The connection is returned to the application.

## Accepting Connections

An endpoint accepts incoming connections by declaring one or more ALPN protocol identifiers it supports. When a remote endpoint connects, QUIC's ALPN negotiation selects the matching protocol, and the connection is delivered to the appropriate handler.

The accepting endpoint learns the peer's Endpoint ID from the TLS handshake. The application can then decide whether to accept or reject the connection based on this identity.

## Streams

QUIC streams are the primary mechanism for exchanging data over a connection. They are extremely lightweight — creating a new stream requires no network round-trip — and many streams can be active concurrently without blocking each other.

There are two stream types:

- **Unidirectional**: Only the initiator can send data. The receiver can only read.
- **Bidirectional**: Both sides can send and receive data. However, the initiator must send data before the receiver becomes aware of the stream.

Streams are created lazily on the network: calling `open_bi()` or `open_uni()` does not immediately notify the peer. The peer's corresponding `accept_bi()` or `accept_uni()` only returns once the initiator has actually sent data on the stream.

## Datagrams

In addition to streams, QUIC supports unreliable datagrams. These are individual messages that are sent without ordering or reliability guarantees, similar to UDP but with the benefit of QUIC's encryption. Datagrams are useful for latency-sensitive data where occasional loss is acceptable.

## Connection Lifecycle

A connection remains active as long as both endpoints keep it open. Iroh sends periodic keepalive probes (every 5 seconds by default) to maintain the connection and detect failures.

Connections can end in several ways:
- **Graceful close**: Either side sends a close frame with an application-defined error code and reason.
- **Idle timeout**: If no data or keepalive is received within the idle timeout period, the connection is considered lost.
- **Transport error**: A QUIC-level error terminates the connection.
- **Path failure**: All paths to the remote endpoint become unreachable.

## Path Migration

A single iroh connection can transparently migrate between network paths during its lifetime. If an endpoint's network changes (e.g., switching from Wi-Fi to cellular), QUIC's connection migration allows the connection to continue on the new path without interruption. This also allows connections to migrate from relay to direct paths after successful hole punching.
