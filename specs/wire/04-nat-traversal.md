# NAT Traversal

**Version:** 1.0

Iroh uses two mechanisms for NAT traversal: a modified form of QUIC Address Discovery (QAD) for learning public addresses, and n0 NAT Traversal (n0-QNT) — a protocol inspired by draft-seemann-quic-nat-traversal but simplified into n0's own protocol — for coordinated hole punching. Both are implemented in [noq](https://github.com/n0-computer/noq), iroh's QUIC library.

## QUIC Address Discovery (QAD)

Iroh implements a modified form of [draft-ietf-quic-address-discovery](https://quicwg.org/address-discovery/draft-ietf-quic-address-discovery.html) for endpoints to learn their public IP address and port as observed by relay servers.

### Modifications from the Draft

Iroh's QAD implementation in noq differs from the standard draft in the following ways:

1. **Sequence numbers on observed address frames.** The `OBSERVED_ADDRESS` frame includes a monotonically increasing `seq_no` field (QUIC VarInt) that is not present in the draft. This allows recipients to detect reordering and identify the most recent observation.

2. **Separate IPv4 and IPv6 frame types.** Instead of a single `OBSERVED_ADDRESS` frame type, noq defines two:

   | Frame Type | ID | Description |
   |------------|-----|-------------|
   | `OBSERVED_IPV4_ADDR` | `0x9f81a6` | Reports an observed IPv4 address |
   | `OBSERVED_IPV6_ADDR` | `0x9f81a7` | Reports an observed IPv6 address |

3. **Persistent connections.** Rather than one-shot probes, iroh maintains long-lived QAD connections to relay servers and continuously monitors for address changes via a streaming interface. This enables real-time detection of NAT rebinding events.

4. **IPv4-mapped IPv6 canonicalization.** When a QAD probe is sent to an IPv4 address but the observed address is reported as an IPv4-mapped IPv6 address (e.g., `::ffff:1.2.3.4`), the client canonicalizes it to a plain IPv4 address.

5. **Tuned initial RTT.** QAD client connections use an initial RTT estimate of 111ms (rather than the QUIC default). This sacrifices initial throughput (acceptable since QAD carries no application data) but yields a 999ms probe timeout, enabling fast failure detection when a path is non-functional (e.g., IPv6 probes on an IPv4-only network).

### Observed Address Frame Format

```
+---------------+-----------+--------+--------+
| Frame Type    | seq_no    | ip     | port   |
| (VarInt)      | (VarInt)  | (4/16B)| (2B)   |
+---------------+-----------+--------+--------+
```

The `ip` field is 4 bytes for `OBSERVED_IPV4_ADDR` or 16 bytes for `OBSERVED_IPV6_ADDR`. The `port` is a 16-bit big-endian unsigned integer.

### QAD Transport Parameter

QAD roles are negotiated via the `ObservedAddr` transport parameter (ID `0x9f81a176`). The role values are:

| Value | Role | Description |
|-------|------|-------------|
| 0 | SendOnly | Reports addresses to peers, does not receive reports |
| 1 | ReceiveOnly | Receives reports, does not report to peers |
| 2 | Both | Reports and receives |

If the transport parameter is absent, QAD is disabled for that endpoint.

### QAD Service

Relay servers MUST expose a QAD service as a QUIC endpoint with the following ALPN:

```
/iroh-qad/0
```

The QAD service operates as follows:

1. The client connects to the relay's QAD QUIC endpoint.
2. The server is configured with role `SendOnly` (sends observed address reports).
3. The client is configured with role `ReceiveOnly` (receives observed address reports).
4. The server observes the client's source address and reports it via `OBSERVED_IPV4_ADDR` or `OBSERVED_IPV6_ADDR` frames.
5. The client receives the observed address and tracks it continuously for changes.

### QAD Client Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Initial RTT | 111ms | Yields ~999ms probe timeout for fast failure |
| Keep-alive interval | 25 seconds | Maintains the persistent QAD connection |
| Max idle timeout | 35 seconds | Connection idle timeout |

### Integration with Endpoint Discovery

QAD is used during network reporting (see [Endpoint Discovery](07-endpoint-discovery.md)). The endpoint runs QAD probes to relay servers to discover:

- Its global IPv4 address
- Its global IPv6 address
- Whether NAT mapping varies by destination (symmetric NAT detection)

These discovered addresses become NAT traversal candidates for hole punching.

### Observed Address Reports on Peer Connections

Endpoints SHOULD send observed address reports on every new path established with a peer. This allows both sides to learn their address as seen by the peer, which may differ from the address observed by relay servers.

## n0 NAT Traversal (n0-QNT)

Iroh implements **n0 NAT Traversal**, a protocol inspired by [draft-seemann-quic-nat-traversal](https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-01.html) but simplified into n0's own protocol. The implementation lives in noq's `n0_nat_traversal` module.

### Differences from draft-seemann-quic-nat-traversal

The key simplifications and changes from the draft are:

1. **Custom transport parameter.** n0-QNT uses its own transport parameter (`N0NatTraversal`, ID `0x3d7f91120401`) instead of the draft's transport parameters. The value is a single byte indicating the maximum number of remote NAT traversal addresses accepted.

2. **Simplified frame set.** Instead of the draft's `PUNCH_ME_NOW` frame, n0-QNT uses `ADD_ADDRESS`, `REMOVE_ADDRESS`, and `REACH_OUT` frames with IPv4/IPv6 variants:

   | Frame Type | ID | Direction | Description |
   |------------|-----|-----------|-------------|
   | `ADD_IPV4_ADDRESS` | `0x3d7f90` | Server → Client | Advertise an IPv4 candidate address |
   | `ADD_IPV6_ADDRESS` | `0x3d7f91` | Server → Client | Advertise an IPv6 candidate address |
   | `REACH_OUT_AT_IPV4` | `0x3d7f92` | Client → Server | Request probing at an IPv4 address |
   | `REACH_OUT_AT_IPV6` | `0x3d7f93` | Client → Server | Request probing at an IPv6 address |
   | `REMOVE_ADDRESS` | `0x3d7f94` | Server → Client | Remove a previously advertised address |

3. **Round-based probing.** NAT traversal attempts are organized into numbered rounds. Starting a new round cancels the previous one and clears pending probes. This prevents stale attempts from interfering with new ones.

4. **Off-path probing with retry.** The server-side sends `PATH_CHALLENGE` frames to client-advertised addresses (off-path), retrying up to 10 times per address (`MAX_OFF_PATH_PROBE_ATTEMPTS`).

5. **Side-based roles.** The QUIC connection's client/server side determines the NAT traversal role: the client collects and sends `REACH_OUT` frames; the server advertises addresses via `ADD_ADDRESS` and probes client addresses via `PATH_CHALLENGE`.

### Frame Formats

#### ADD_ADDRESS (ADD_IPV4_ADDRESS / ADD_IPV6_ADDRESS)

Sent by the server side to advertise a candidate address to the client.

```
+---------------+-----------+--------+--------+
| Frame Type    | seq_no    | ip     | port   |
| (VarInt)      | (VarInt)  | (4/16B)| (2B)   |
+---------------+-----------+--------+--------+
```

The `seq_no` is a monotonically increasing identifier for this address within the connection. It is used to reference the address in `REMOVE_ADDRESS` frames.

#### REACH_OUT (REACH_OUT_AT_IPV4 / REACH_OUT_AT_IPV6)

Sent by the client side to signal the server to probe at the given address.

```
+---------------+-----------+--------+--------+
| Frame Type    | round     | ip     | port   |
| (VarInt)      | (VarInt)  | (4/16B)| (2B)   |
+---------------+-----------+--------+--------+
```

The `round` field is a monotonically increasing round number. When the server receives a `REACH_OUT` with a higher round number than the current round, it cancels all pending probes from the previous round.

#### REMOVE_ADDRESS

Sent by the server side to remove a previously advertised address.

```
+---------------+-----------+
| Frame Type    | seq_no    |
| (VarInt)      | (VarInt)  |
+---------------+-----------+
```

### Transport Parameter

n0-QNT is negotiated via the `N0NatTraversal` transport parameter:

| Parameter ID | Value Format | Description |
|-------------|-------------|-------------|
| `0x3d7f91120401` | 1 byte (u8) | Maximum number of remote NAT traversal addresses accepted |

If this transport parameter is absent from either side's transport parameters, n0-QNT is not negotiated and NAT traversal frames MUST NOT be sent.

### Protocol Flow

1. **Negotiation**: Both sides advertise the `N0NatTraversal` transport parameter during the QUIC handshake.
2. **Address advertisement**: The server side sends `ADD_ADDRESS` frames for each of its candidate addresses.
3. **Candidate collection**: The client side collects its local addresses and registers them internally.
4. **Round initiation**: The client sends `REACH_OUT` frames — one per local address — containing the current round number. This tells the server which addresses to probe.
5. **Off-path probing**: The server sends `PATH_CHALLENGE` frames to each address received in `REACH_OUT` frames (up to 10 attempts per address).
6. **Path establishment**: If a `PATH_CHALLENGE` succeeds, a new QUIC multipath path is established.
7. **Subsequent rounds**: The client MAY initiate new rounds with fresh candidates. Each new round cancels pending probes from the previous round.

### Roles (iroh layer)

Only the **client** side of a connection SHOULD initiate NAT traversal rounds. This avoids conflicting simultaneous attempts from both sides.

### Connection Arbitration (iroh layer)

When multiple connections exist between two endpoints, only the connection with the **lowest Connection ID** SHOULD perform NAT traversal. This prevents redundant hole punching attempts. Successful paths discovered by one connection MUST be opened on all other connections to the same remote endpoint.

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
| Max off-path probe attempts | 10 | Maximum retries for a single off-path PATH_CHALLENGE |

### Triggers

NAT traversal SHOULD be triggered when:

1. A new connection is established via relay
2. Local network addresses change
3. New remote candidate addresses are received
4. A network change is detected (e.g., Wi-Fi to cellular)
5. The periodic upgrade interval expires

NAT traversal SHOULD NOT be triggered when the current direct path has RTT below the "good enough" threshold.
