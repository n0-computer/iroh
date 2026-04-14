# Overview

**Version:** 1.0

Iroh is a peer-to-peer networking library that provides encrypted QUIC connections between endpoints. It establishes direct connectivity using hole punching, with relay servers as a fallback to guarantee that any two endpoints can always communicate.

## Design Philosophy

Iroh is designed as a composition of existing IETF standards and drafts. Rather than inventing new protocols, iroh profiles and combines established specifications to build a complete peer-to-peer connectivity stack:

| Component | Specification |
|-----------|--------------|
| Transport | [QUIC v1 (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000) |
| Encryption | [TLS 1.3 (RFC 8446)](https://www.rfc-editor.org/rfc/rfc8446) with [Raw Public Keys (RFC 7250)](https://www.rfc-editor.org/rfc/rfc7250) |
| Multipath | [QUIC Multipath (draft-ietf-quic-multipath)](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) |
| Address Discovery | Modified [QUIC Address Discovery (draft-ietf-quic-address-discovery)](https://quicwg.org/address-discovery/draft-ietf-quic-address-discovery.html) |
| NAT Traversal | n0-QNT, inspired by [QUIC NAT Traversal (draft-seemann-quic-nat-traversal)](https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-01.html) |
| Endpoint Discovery | [Pkarr](https://github.com/Nuhvi/pkarr/blob/main/design/base.md) |

QUIC, multipath, and the modified QAD/QNT protocols are implemented in [noq](https://github.com/n0-computer/noq), iroh's QUIC library (a fork of Quinn).

The iroh relay protocol is the primary iroh-specific addition — a lightweight packet forwarding protocol that ensures connectivity when direct paths are unavailable.

## Core Concepts

### Endpoints

An iroh endpoint is a network participant identified by an Ed25519 public key, called its **Endpoint ID**. The endpoint manages QUIC connections, relay server communication, address discovery, and hole punching. Every endpoint has a corresponding secret key used for authentication and encryption.

### Connections

Iroh connections are standard QUIC connections carrying TLS 1.3 encryption. They support bidirectional and unidirectional streams, datagrams, and 0-RTT resumption. Application protocols are negotiated using ALPN (Application-Layer Protocol Negotiation).

### Relay Servers

Relay servers are publicly-reachable infrastructure that forward encrypted packets between endpoints. An endpoint connects to the relay server with the lowest latency and designates it as its **home relay**. Relay servers cannot decrypt traffic — they forward opaque QUIC packets based on the destination Endpoint ID. Relays also provide QUIC Address Discovery (QAD) services to help endpoints learn their public addresses.

### Hole Punching

When two endpoints communicate via a relay, iroh simultaneously attempts to establish a direct connection through NAT traversal. It uses QUIC Address Discovery to learn public addresses and QUIC NAT Traversal to coordinate hole punching. Once a direct path is validated, traffic migrates from the relay to the direct connection. If hole punching fails, the relay connection remains as a permanent fallback.

### Address Lookup

Address lookup is a pluggable system for resolving an Endpoint ID to the network addresses needed to connect. The primary implementation uses DNS records published via Pkarr (Public Key Addressable Resource Records), which allows endpoints to publish their relay URL and direct addresses as signed DNS records keyed by their public key.

### Transports

Iroh supports multiple transport types simultaneously: IPv4 UDP, IPv6 UDP, relay (WebSocket), and custom transports (such as Tor or Bluetooth). QUIC multipath allows a single connection to span multiple transports concurrently, enabling seamless failover and path migration.
