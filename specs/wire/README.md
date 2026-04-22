# Iroh Wire Protocol Specification v1.0

This specification defines the wire-level protocol details of iroh. It is intended for iroh engineers and anyone implementing or analyzing the iroh protocol at the byte level.

For a high-level conceptual overview, see the [Design specification](../design/README.md).

**Version:** 1.1

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in these documents are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Table of Contents

1. [Overview](01-overview.md) — Protocol stack, referenced specifications, terminology
2. [TLS](02-tls.md) — TLS 1.3 profile with Raw Public Keys
3. [QUIC](03-quic.md) — QUIC profile, multipath configuration, parameters
4. [NAT Traversal](04-nat-traversal.md) — QAD, QNT, and holepunching coordination
5. [Relay Protocol](05-relay-protocol.md) — Relay framing, handshake, message types
6. [Addressing](06-addressing.md) — Address encoding, DNS records, Pkarr packets
7. [Endpoint Discovery](07-endpoint-discovery.md) — Net report, relay selection, address publication
