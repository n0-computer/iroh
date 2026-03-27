# Endpoint Shutdown

Shutting down an iroh `Endpoint` is a coordinated multi-phase process. It must gracefully
close QUIC connections, stop all actor tasks, and release transport resources.

## Shutdown Sequence

<!-- BEGIN GENERATED SECTION
Source: iroh/src/socket.rs
Prompt: Read the ShutdownState struct, EndpointInner::close() and Drop impl,
        and the Actor task shutdown logic. Generate a sequenceDiagram showing the
        shutdown sequence with the phases and their coordination tokens.
-->

```mermaid
sequenceDiagram
    participant User
    participant Endpoint as Endpoint / EndpointInner
    participant Shutdown as ShutdownState
    participant NoqEndpoint as noq::Endpoint
    participant Actor as Socket Actor
    participant Transports as Transports + Relays

    User->>Endpoint: close(error_code, reason)
    Endpoint->>Shutdown: cancel at_close_start
    Note over Shutdown: is_closing() = true

    Endpoint->>NoqEndpoint: close(error_code, reason)
    Note over NoqEndpoint: Drain existing connections

    NoqEndpoint-->>Shutdown: cancel at_endpoint_closed
    Note over Shutdown: QUIC layer drained

    Note over Actor: Must exit within 100ms
    Actor->>Transports: shutdown relay actors, close sockets
    Actor-->>Shutdown: actor task completes

    Shutdown->>Shutdown: closed = true
    Note over Shutdown: is_closed() = true
```

### Phases

| Phase | Token / Flag | Meaning |
|-------|-------------|---------|
| 1. Close initiated | `at_close_start` cancelled | `Endpoint::close()` called |
| 2. QUIC drained | `at_endpoint_closed` cancelled | `noq::Endpoint` finished draining |
| 3. Actor exit | (task completes) | Actor must exit within 100ms of phase 2 |
| 4. Fully closed | `closed = true` | All resources released |

### Drop Safety

If `Endpoint` is dropped without calling `close()`, the `Drop` impl on `EndpointInner`
logs an error and calls `abort()`, which is an ungraceful shutdown. Always call
`Endpoint::close()` for clean shutdown.

<!-- END GENERATED SECTION -->

## ShutdownState

The `ShutdownState` struct coordinates shutdown across multiple async tasks:

```rust
struct ShutdownState {
    at_close_start: CancellationToken,      // Phase 1
    at_endpoint_closed: CancellationToken,  // Phase 2
    closed: AtomicBool,                      // Phase 4
}
```

**Query methods:**
- `is_closing()` — true once `close()` is called (phases 1-4)
- `is_closed()` — true only when everything is fully stopped (phase 4)
