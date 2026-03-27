# Remote State Actor

For each remote endpoint, a `RemoteStateActor` manages all connections, paths, holepunching,
and path selection. It's the central per-peer orchestrator.

## What It Does

1. **Tracks connections** — registers QUIC connections, monitors their path events
2. **Manages paths** — maintains known paths via `RemotePathState` (see [path-lifecycle.md](path-lifecycle.md))
3. **Drives holepunching** — triggers NAT traversal attempts, throttled to every 5s
4. **Selects the best path** — prefers direct IP over relay, lowest RTT among IP paths
5. **Runs address lookup** — discovers new paths via DNS, mDNS, Pkarr

## Event Loop

The actor runs a `tokio::select!` loop responding to:
- Inbox messages (new connections, datagrams, network changes)
- Path events from QUIC (path opened/closed/degraded)
- NAT traversal candidate updates
- Scheduled holepunch and path-open timers
- Address lookup results
- Periodic connection quality checks (every 60s)
- Idle timeout (60s with no connections)

## Path Selection

The actor maintains a `selected_path` that is the currently preferred route:

- **Direct IP preferred** over relay (configurable via transport bias)
- **Lowest RTT wins** among IP paths, with a 5ms minimum switching threshold
- **10ms is "good enough"** — below this latency, no further upgrade attempts
- **Upgrade checks every 60s** — even with a working path, holepunching continues

## Holepunching

Holepunching triggers when:
- A new connection is added
- Local addresses change
- NAT traversal candidates update
- A scheduled timer fires

Throttled to one attempt every 5s. Skipped if NAT candidates haven't changed.

## Lifecycle

The actor starts when the first connection to a remote is established, and stops after
60s idle (no connections, no pending messages). Stopping is cheap — the actor restarts
transparently when needed, carrying over any leftover messages.
