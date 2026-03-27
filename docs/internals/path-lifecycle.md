# Path Lifecycle

A "path" in iroh is a network route to a remote endpoint. Each remote endpoint can have
many paths: direct IP, via relay, or via custom transports. Paths are discovered, tested
via holepunching, used, and eventually pruned.

## Path Types

Paths are identified by `transports::Addr`, which has three variants:
- **`Ip(SocketAddr)`** — Direct UDP path
- **`Relay(RelayUrl, EndpointId)`** — Path through a relay server
- **`Custom(CustomAddr)`** — Custom transport path

## Path Status State Machine

Each path has a `PathStatus` that tracks its usability.

<!-- BEGIN GENERATED SECTION
Source: iroh/src/socket/remote_map/remote_state/path_state.rs
Prompt: Read the PathStatus enum and the methods insert_open_path(), abandoned_path(),
        and insert_multiple(). Generate a stateDiagram-v2 showing all status transitions
        with the method that triggers each. Also read the prune_non_relay_paths() function
        and document which states get pruned.
-->

```mermaid
stateDiagram-v2
    [*] --> Unknown : insert_multiple() / new path discovered

    Unknown --> Open : insert_open_path()
    Unknown --> Unusable : abandoned_path()

    Open --> Inactive : abandoned_path()
    Open --> Open : insert_open_path() (re-confirmed)

    Inactive --> Inactive : abandoned_path() (timestamp updated)
    Inactive --> Open : insert_open_path()
    Inactive --> PRUNED : prune_non_relay_paths()

    Unusable --> Open : insert_open_path()
    Unusable --> Unusable : abandoned_path()
    Unusable --> PRUNED : prune_non_relay_paths()

    state PRUNED <<choice>>
    PRUNED --> [*] : path removed from map
```

### States

| Status | Meaning | Default |
|--------|---------|---------|
| `Unknown` | Not yet attempted or holepunch in progress | Yes (default) |
| `Open` | Path is active and working | |
| `Inactive(Instant)` | Was once open, closed at the given time | |
| `Unusable` | Holepunch was attempted and failed | |

### Transition Details

| From | To | Trigger | Code |
|------|----|---------|------|
| (new) | `Unknown` | `insert_multiple()` — address lookup discovers new addresses | `path_state.rs` |
| `Unknown` | `Open` | `insert_open_path()` — holepunch succeeds or direct connection works | `path_state.rs` |
| `Unknown` | `Unusable` | `abandoned_path()` — holepunch attempted, didn't work | `path_state.rs` |
| `Open` | `Inactive` | `abandoned_path()` — path was open but is now closed | `path_state.rs` |
| `Inactive` | `Inactive` | `abandoned_path()` — timestamp refreshed, stays inactive | `path_state.rs` |
| `Inactive` | `Open` | `insert_open_path()` — path re-established | `path_state.rs` |
| `Unusable` | `Open` | `insert_open_path()` — retry succeeded | `path_state.rs` |
| `Unusable` | `Unusable` | `abandoned_path()` — still unusable | `path_state.rs` |

<!-- END GENERATED SECTION -->

## Path Pruning

Pruning prevents unbounded growth of the path map. It only applies to non-relay paths
and only triggers when the total count exceeds `MAX_NON_RELAY_PATHS` (30).

<!-- BEGIN GENERATED SECTION
Source: iroh/src/socket/remote_map/remote_state/path_state.rs
Prompt: Read the prune_non_relay_paths() function and the constants MAX_NON_RELAY_PATHS
        and MAX_INACTIVE_NON_RELAY_PATHS. Generate a flowchart showing the pruning decision
        logic.
-->

```mermaid
flowchart TD
    A[prune_non_relay_paths called] --> B{total paths < 30?}
    B -->|yes| Z[no pruning]
    B -->|no| C{non-relay paths < 30?}
    C -->|yes| Z
    C -->|no| D[classify non-relay paths]
    D --> E[Open / Unknown: keep always]
    D --> F[Unusable: mark for removal]
    D --> G[Inactive: sort by close time]
    F --> H{all paths Unusable?}
    H -->|yes| I[keep 30, remove rest]
    H -->|no| J[remove all Unusable]
    G --> K[keep 10 most recent Inactive]
    K --> L[remove older Inactive paths]
    J --> M[apply removals]
    L --> M
    I --> M
```

### Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_NON_RELAY_PATHS` | 30 | Max non-relay paths before pruning triggers |
| `MAX_INACTIVE_NON_RELAY_PATHS` | 10 | How many inactive (previously-working) paths to keep |

<!-- END GENERATED SECTION -->

## Path Sources

Each path tracks how it was discovered via `Source`:
- **UDP** — Discovered via direct UDP communication
- **Relay** — Learned through relay communication
- **AddressLookup** — Found via DNS, mDNS, Pkarr, or other discovery mechanisms

The source and timestamp are stored in `PathState::sources`, keeping only the latest
timestamp per source type.
