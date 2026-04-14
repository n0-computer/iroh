# Identity

**Version:** 1.0

Every iroh endpoint has a cryptographic identity based on an Ed25519 key pair. This identity is used for authentication, encryption, and addressing.

## Endpoint ID

An endpoint's identity is its Ed25519 public key, called the **Endpoint ID**. This is a 32-byte value that uniquely identifies the endpoint across the network. The corresponding secret key is held privately and never transmitted.

The Endpoint ID serves three roles:
- **Identity**: It is the stable, globally unique identifier for the endpoint.
- **Authentication**: During TLS handshake, each side proves possession of their secret key and verifies the peer's Endpoint ID.
- **Addressing**: It is used as a lookup key for address discovery (see [Address Lookup](address-lookup.md)) and as a routing key by relay servers.

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
