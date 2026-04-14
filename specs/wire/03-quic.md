# QUIC

**Version:** 1.0

Iroh uses QUIC v1 ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)) as its transport protocol, with the multipath extension and specific parameter choices.

## QUIC Version

Implementations MUST use QUIC v1 as defined in [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000).

## Multipath

Iroh uses the QUIC Multipath extension ([draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/)) to manage concurrent network paths within a single connection.

Implementations MUST support multipath with the following parameters:

| Parameter | Value |
|-----------|-------|
| Maximum concurrent paths | 12 |

Multipath is used for:
- Simultaneous relay and direct paths during hole punching
- Concurrent IPv4 and IPv6 paths
- Path probing without disrupting active traffic
- Seamless migration between transports

## QUIC Bit

QUIC bit greasing MUST be disabled. The first byte of non-QUIC packets is set to zero so that the QUIC implementation can distinguish QUIC packets from other traffic sharing the same socket. Implementations MUST NOT set the QUIC bit to random values.

## Connection Parameters

The following QUIC transport parameters MUST be used:

### Keepalive

| Parameter | Value |
|-----------|-------|
| Connection keepalive interval | 5 seconds |
| Per-path keepalive interval | 5 seconds |

Endpoints MUST send keepalive probes at these intervals to maintain NAT bindings and detect path failures.

### Idle Timeout

| Path Type | Idle Timeout |
|-----------|-------------|
| Direct (IP) paths | 15 seconds |
| Relay paths | 30 seconds |

Relay paths use a longer idle timeout because they serve as the fallback transport and SHOULD be maintained even when direct paths are preferred.

### NAT Traversal Addresses

| Parameter | Value |
|-----------|-------|
| Maximum NAT traversal addresses | 12 |

Endpoints MAY advertise up to 12 addresses for NAT traversal candidate exchange.

### Observed Address Reports

Endpoints SHOULD enable sending and receiving observed address reports as defined in [QAD](https://quicwg.org/address-discovery/draft-ietf-quic-address-discovery.html). Observed address reports SHOULD be sent on every new path to assist the peer in discovering its public address.

## Address Mapping

QUIC requires socket addresses (IPv4 or IPv6) for path identification. To support non-IP transports (relay, custom), iroh maps these to synthetic IPv6 addresses in the Unique Local Address (ULA) range `fd00::/8`.

The mapping is internal to the iroh implementation. The QUIC layer operates on standard IPv6 addresses while the transport layer translates between mapped addresses and underlying transport mechanisms.

### Mapped Address Types

| Transport | Mapped Address Range |
|-----------|---------------------|
| IP (direct) | Actual IPv4/IPv6 address (no mapping) |
| Relay | `fd00::{relay_hash}::{endpoint_id_hash}` |
| Custom | `fd00::{custom_id}::{address_hash}` |

For initial QUIC packets before a specific transport is selected, a mixed mapped address is used to represent the remote endpoint generically.
