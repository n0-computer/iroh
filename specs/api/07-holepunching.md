# Holepunching

**Version:** 1.0

Holepunching is the process of establishing a direct connection between two endpoints that are both behind NATs or firewalls. Iroh performs holepunching automatically in the background whenever two endpoints are communicating via a relay.

## Strategy: Relay First, Then Upgrade

Iroh's approach to connectivity follows a "relay first, upgrade later" strategy:

1. **Connect via relay**: The initial connection is established through a relay server. This always works, regardless of network topology, because both endpoints have outbound connections to the relay.
2. **Discover addresses**: While the relay connection is active, both endpoints discover their own public addresses using QUIC Address Discovery (QAD) and exchange them with the peer.
3. **Attempt direct paths**: Both endpoints simultaneously attempt to open direct paths to each other's discovered addresses.
4. **Validate and migrate**: Once a direct path is validated, traffic migrates from the relay to the direct connection.
5. **Keep relay as fallback**: The relay path remains available as a backup in case the direct path fails.

This approach guarantees that connectivity is always available (via relay) while optimizing for direct connections whenever possible.

## Address Discovery

Before holepunching can begin, each endpoint needs to know its own public address — the IP and port as seen from outside its NAT. Iroh uses a modified form of QUIC Address Discovery (QAD), based on [draft-ietf-quic-address-discovery](https://quicwg.org/address-discovery/draft-ietf-quic-address-discovery.html), implemented in [noq](https://github.com/n0-computer/noq).

Each endpoint maintains a persistent connection to the QAD service on its relay server (ALPN `/iroh-qad/0`). The relay server observes the endpoint's public address and continuously reports it back. This discovered address becomes a NAT traversal candidate. The persistent connection allows real-time detection of address changes (e.g., NAT rebinding).

Key modifications from the standard QAD draft include separate IPv4/IPv6 frame types, sequence numbers on observed address frames, and tuned connection parameters for fast failure detection. See the [wire spec](../wire/04-nat-traversal.md) for details.

Additionally, the endpoint's network report collects information about its NAT behavior, including:
- Whether UDP works on IPv4 and IPv6
- Whether the NAT mapping varies by destination (symmetric NAT)
- The endpoint's global IPv4 and IPv6 addresses

## Coordinated Holepunching

Iroh implements **n0 NAT Traversal (n0-QNT)**, a protocol inspired by [draft-seemann-quic-nat-traversal](https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-01.html) but simplified into n0's own protocol, also implemented in noq. The key differences from the draft include a custom transport parameter, a simplified frame set (`ADD_ADDRESS`, `REACH_OUT`, `REMOVE_ADDRESS`), round-based probing, and off-path probing with retry. See the [wire spec](../wire/04-nat-traversal.md) for the full protocol details.

The process works as follows:

1. **Candidate collection**: Each endpoint collects its local addresses (from network interfaces) and public addresses (from QAD). These become NAT traversal candidates.
2. **Candidate exchange**: Candidates are exchanged between endpoints using QUIC protocol frames over the existing relay-mediated connection.
3. **Simultaneous probing**: Both endpoints simultaneously attempt to send QUIC packets to each other's candidates. This creates NAT bindings on both sides, which is the essence of hole punching.
4. **Path validation**: QUIC's path validation mechanism confirms which paths actually work.
5. **Path promotion**: Working direct paths are promoted and traffic migrates from the relay.

Only the **client** side of a connection initiates holepunching. When multiple connections exist to the same remote endpoint, only the connection with the lowest connection ID performs the holepunch to avoid conflicting attempts. Successful paths are then opened on all connections to that peer.

## Path Selection

When multiple paths are available (relay, direct IPv4, direct IPv6), iroh selects the best path based on:

- **Transport priority**: Direct paths are preferred over relay paths.
- **IPv6 preference**: IPv6 gets a small RTT advantage (3ms bias) to prefer it when latencies are similar.
- **RTT**: Among paths of the same priority, the one with the lowest round-trip time wins.
- **Switching threshold**: A minimum RTT difference (5ms) is required to switch paths, preventing flapping between similar paths.

If the current path has latency under 10ms, iroh considers it "good enough" and stops actively trying to find better paths.

## Retry and Persistence

Holepunching is not a one-shot process. Iroh continues attempting to establish direct connections:

- **On new candidates**: Whenever new address candidates are discovered, holepunching is retried immediately.
- **Periodic retries**: If candidates haven't changed, retries occur every 5 seconds.
- **Periodic upgrades**: Even after a direct path is established, iroh periodically (every 60 seconds) checks for better paths.
- **Network changes**: When the endpoint's network changes (e.g., Wi-Fi to cellular), holepunching is triggered immediately.

## When Holepunching Fails

If no direct path can be established, the relay connection remains as a permanent fallback. The connection continues to work — with higher latency and through the relay server — but is otherwise fully functional. Iroh continues periodic holepunch attempts in case network conditions change.
