# Transports

**Version:** 1.0

Iroh supports multiple transport types simultaneously, allowing a single QUIC connection to span different network technologies. This is enabled by QUIC multipath, which manages concurrent paths across transports.

## Transport Types

### IPv4 and IPv6 UDP

The primary transport is standard UDP sockets. Iroh binds to both IPv4 and IPv6 sockets when available and uses them for direct peer-to-peer communication. These are the preferred transports for direct connections after successful hole punching.

### Relay

The relay transport carries QUIC packets over WebSocket connections to relay servers. It is the fallback transport that guarantees connectivity when direct paths are unavailable. See [Relays](relays.md) for details on the relay protocol.

### Custom Transports

Iroh's transport layer is extensible. Custom transports can be implemented for non-IP networks such as Tor, Bluetooth Low Energy, or any other communication channel. Each custom transport is identified by a unique transport ID (see [Addressing](addressing.md) for the registry).

Custom transports integrate with iroh's path selection and multipath systems. They appear as additional paths alongside UDP and relay paths.

## QUIC Multipath

Iroh uses the QUIC Multipath extension ([draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/)) to manage concurrent paths within a single connection. This enables:

- **Seamless failover**: If one path fails (e.g., Wi-Fi disconnects), traffic continues on another path without disrupting the connection.
- **Relay-to-direct migration**: When hole punching succeeds, the connection migrates from the relay path to the direct path without interruption.
- **Path probing**: New candidate paths can be probed in the background while existing paths carry traffic.

Iroh supports up to 12 concurrent multipath paths per connection.

## Path Selection

When multiple paths are available, iroh selects the best one using a bias system:

### Transport Bias

Each transport is classified as either **Primary** or **Backup**:

| Transport | Type | RTT Bias |
|-----------|------|----------|
| IPv4 UDP | Primary | 0ms |
| IPv6 UDP | Primary | -3ms (preferred) |
| Relay | Backup | 0ms |

Primary transports compete for the active path based on RTT. Backup transports are only used when no Primary transport is available.

### Selection Algorithm

1. Sort available paths by `(transport_type, biased_rtt)`.
2. Among Primary paths, select the one with the lowest biased RTT.
3. Require at least 5ms RTT improvement to switch to a different path (prevents flapping).
4. Fall back to Backup paths only when no Primary path is available.

### Path Keepalive

Each path is kept alive with periodic probes:
- **Heartbeat interval**: 5 seconds
- **Direct path idle timeout**: 15 seconds
- **Relay path idle timeout**: 30 seconds (longer because relay is the fallback)

If a path receives no traffic or keepalive within its idle timeout, it is considered dead and closed.

## Address Mapping

To integrate non-IP transports with QUIC (which expects socket addresses), iroh maps relay and custom transport addresses to synthetic IPv6 addresses in the ULA range (`fd00::/8`). This mapping is internal to iroh and transparent to the application. The QUIC layer sees standard IPv6 addresses while the transport layer translates them to the appropriate underlying transport.
