# Overview

**Version:** 1.0

## Protocol Stack

Iroh's protocol stack is layered as follows:

```
┌─────────────────────────────────────┐
│         Application (ALPN)          │
├─────────────────────────────────────┤
│       QUIC v1 + Multipath           │
│  (RFC 9000, draft-ietf-quic-mp)     │
├─────────────────────────────────────┤
│     TLS 1.3 + Raw Public Keys       │
│      (RFC 8446, RFC 7250)           │
├──────────┬──────────┬───────────────┤
│  UDP/IP  │  Relay   │   Custom      │
│          │ (WebSocket)│  Transport   │
└──────────┴──────────┴───────────────┘
```

All layers are standard or based on IETF drafts except the relay protocol, which is iroh-specific.

## Referenced Specifications

| Short Name | Full Title | Reference |
|------------|-----------|-----------|
| QUIC | QUIC: A UDP-Based Multiplexed and Secure Transport | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) |
| QUIC-TLS | Using TLS to Secure QUIC | [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) |
| TLS 1.3 | The Transport Layer Security (TLS) Protocol Version 1.3 | [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) |
| RPK | Transport Layer Security (TLS) Raw Public Keys | [RFC 7250](https://www.rfc-editor.org/rfc/rfc7250) |
| TLS-EKM | Keying Material Exporters for TLS | [RFC 5705](https://www.rfc-editor.org/rfc/rfc5705) |
| QUIC-MP | Multipath Extension for QUIC | [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) |
| QAD | QUIC Address Discovery (modified) | [draft-ietf-quic-address-discovery](https://quicwg.org/address-discovery/draft-ietf-quic-address-discovery.html) |
| n0-QNT | n0 NAT Traversal (inspired by QNT) | [draft-seemann-quic-nat-traversal](https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-01.html) |
| Pkarr | Public Key Addressable Resource Records | [Pkarr Base Design](https://github.com/Nuhvi/pkarr/blob/main/design/base.md) |
| VarInt | QUIC Variable-Length Integer Encoding | [RFC 9000 Section 16](https://www.rfc-editor.org/rfc/rfc9000#section-16) |
| RFC 2119 | Key words for use in RFCs | [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) |

## Terminology

| Term | Definition |
|------|-----------|
| **Endpoint** | A network participant running the iroh protocol. |
| **Endpoint ID** | An Ed25519 public key (32 bytes) that uniquely identifies an endpoint. |
| **Secret Key** | An Ed25519 secret key corresponding to the Endpoint ID. |
| **Home Relay** | The relay server an endpoint is currently connected to with the lowest latency. |
| **Transport** | An underlying network mechanism for carrying QUIC packets (UDP, relay, custom). |
| **Path** | A specific route to a remote endpoint over a particular transport. |
| **ALPN** | Application-Layer Protocol Negotiation identifier. |
| **Pkarr** | A system for publishing DNS records signed by Ed25519 keys. |
| **QAD** | QUIC Address Discovery (modified) — a mechanism for learning one's public address. |
| **n0-QNT** | n0 NAT Traversal — n0's protocol for coordinated hole punching, inspired by QUIC NAT Traversal. |
| **noq** | n0's QUIC library (fork of Quinn), implementing QUIC, multipath, QAD, and n0-QNT. |

## Notation

- Byte lengths are in octets unless stated otherwise.
- Multi-byte integers are big-endian unless stated otherwise.
- Frame type tags use QUIC VarInt encoding ([RFC 9000 Section 16](https://www.rfc-editor.org/rfc/rfc9000#section-16)).
- `EndpointId` on the wire is always 32 raw bytes (Ed25519 public key), no length prefix.
