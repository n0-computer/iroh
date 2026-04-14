# NAT Traversal

**Version:** 1.0

Iroh uses two IETF draft mechanisms for NAT traversal: QUIC Address Discovery (QAD) for learning public addresses, and QUIC NAT Traversal (QNT) for coordinated hole punching.

## QUIC Address Discovery (QAD)

Iroh implements [draft-ietf-quic-address-discovery](https://quicwg.org/address-discovery/draft-ietf-quic-address-discovery.html) for endpoints to learn their public IP address and port as observed by relay servers.

### QAD Service

Relay servers MUST expose a QAD service as a QUIC endpoint with the following ALPN:

```
/iroh-qad/0
```

The QAD service operates as follows:

1. The client connects to the relay's QAD QUIC endpoint.
2. The server enables `send_observed_address_reports`.
3. The client enables `receive_observed_address_reports`.
4. The server observes the client's source address and reports it via QUIC's `OBSERVED_ADDRESS` frame.
5. The client receives the observed address report containing its public IP and port.

### Integration with Endpoint Discovery

QAD is used during network reporting (see [Endpoint Discovery](endpoint-discovery.md)). The endpoint runs QAD probes to relay servers to discover:

- Its global IPv4 address
- Its global IPv6 address
- Whether NAT mapping varies by destination (symmetric NAT detection)

These discovered addresses become NAT traversal candidates for hole punching.

### Observed Address Reports on Peer Connections

Endpoints SHOULD send observed address reports on every new path established with a peer. This allows both sides to learn their address as seen by the peer, which may differ from the address observed by relay servers.

## QUIC NAT Traversal (QNT)

Iroh implements a form of [draft-seemann-quic-nat-traversal](https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-01.html) for coordinated hole punching between endpoints.

### Roles

In a QUIC connection, one side is the **client** (initiator) and the other is the **server** (responder). Only the client-role endpoint SHOULD initiate NAT traversal rounds. This avoids conflicting simultaneous attempts from both sides.

### Connection Arbitration

When multiple connections exist between two endpoints, only the connection with the **lowest Connection ID** SHOULD perform NAT traversal. This prevents redundant hole punching attempts. Successful paths discovered by one connection MUST be opened on all other connections to the same remote endpoint.

### Candidate Exchange

NAT traversal candidates are exchanged between endpoints using QUIC protocol frames over the existing (typically relay-mediated) connection:

1. Each endpoint collects its local addresses from network interfaces.
2. Each endpoint collects its public addresses from QAD observations.
3. Candidates are advertised to the peer via `ADD_ADDRESS`-style frames.
4. The peer forms candidate pairs by combining remote candidates with its own local candidates.

### Hole Punching Process

Once candidates are exchanged:

1. The client initiates a NAT traversal round by signaling the peer to begin simultaneous probing.
2. Both endpoints open QUIC multipath paths to each other's candidate addresses.
3. QUIC path validation (PING/PONG) confirms which paths are reachable.
4. Initially, new paths are opened with `PATH_STATUS_BACKUP`.
5. Once validated and selected, the path status is promoted to `PATH_STATUS_AVAILABLE`.

### Path Status Transitions

```
BACKUP ──(validated + selected)──> AVAILABLE
```

New NAT traversal paths MUST initially be opened with backup status to avoid disrupting the active relay path. Only after successful validation and path selection SHOULD a direct path be promoted to available status.

### Timing Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Holepunch attempt interval | 5 seconds | Minimum time between attempts with unchanged candidates |
| Upgrade interval | 60 seconds | Periodic check for better paths on established connections |
| Good enough latency | 10 ms | If current path RTT is below this, stop actively seeking better paths |

### Triggers

NAT traversal SHOULD be triggered when:

1. A new connection is established via relay
2. Local network addresses change
3. New remote candidate addresses are received
4. A network change is detected (e.g., Wi-Fi to cellular)
5. The periodic upgrade interval expires

NAT traversal SHOULD NOT be triggered when the current direct path has RTT below the "good enough" threshold.
