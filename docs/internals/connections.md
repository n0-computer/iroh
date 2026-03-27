# Connection Lifecycle

Connections are how iroh endpoints communicate. A `Connection` wraps a QUIC connection
(via `noq::Connection`) and adds iroh-specific functionality: endpoint identity verification,
path management, and integration with the iroh socket layer.

## Overview

There are multiple transitional types between initiating a connection and having a fully
established, cryptographically verified connection. The path diverges based on whether
the connection is outgoing (client) or incoming (server), and whether 0-RTT is used.

<!-- BEGIN GENERATED SECTION
Source: iroh/src/endpoint/connection.rs
Prompt: Read all the public types in this module. Generate a stateDiagram-v2 showing
        the lifecycle of both outgoing and incoming connections, including the 0-RTT paths.
        Show the type name at each state and the method that transitions between states.
-->

```mermaid
stateDiagram-v2
    state "Outgoing (Client)" as outgoing {
        [*] --> Connecting : Endpoint::connect()
        Connecting --> Connection : .await (handshake completes)
        Connecting --> OutgoingZeroRttConnection : .into_0rtt()
        Connecting --> ConnectingError : handshake fails

        OutgoingZeroRttConnection --> ZeroRttAccepted : .handshake_completed()
        OutgoingZeroRttConnection --> ZeroRttRejected : .handshake_completed()

        state ZeroRttAccepted <<choice>>
        state ZeroRttRejected <<choice>>
        ZeroRttAccepted --> Connection : ZeroRttStatus::Accepted
        ZeroRttRejected --> Connection : ZeroRttStatus::Rejected
    }

    state "Incoming (Server)" as incoming {
        [*] --> Accept : Endpoint::accept()
        Accept --> Incoming : connection arrives
        Incoming --> Accepting : .accept()
        Incoming --> Accepting : .accept_with(config)
        Incoming --> [*] : .refuse() / .ignore()
        Incoming --> RetryError : .retry()

        Accepting --> Connection : .await (handshake completes)
        Accepting --> IncomingZeroRttConnection : .into_0rtt()
        Accepting --> ConnectingError : handshake fails

        IncomingZeroRttConnection --> Connection : .handshake_completed()
    }

    state "Established" as established {
        Connection --> [*] : .close(code, reason)
        Connection --> [*] : connection error
    }
```

### Types

| Type | Role | Side |
|------|------|------|
| `Accept` | Future from `Endpoint::accept()`, yields `Incoming` | Server |
| `Incoming` | Pre-handshake incoming connection; can accept, refuse, retry, or ignore | Server |
| `Accepting` | Server-side connection during TLS handshake | Server |
| `Connecting` | Client-side connection during TLS handshake | Client |
| `Connection` | Fully established, authenticated QUIC connection | Both |
| `OutgoingZeroRttConnection` | Client-side 0-RTT connection (may be rejected) | Client |
| `IncomingZeroRttConnection` | Server-side 0-RTT/0.5-RTT connection | Server |

### Key Transitions

| From | To | Method | Notes |
|------|----|--------|-------|
| `Incoming` | `Accepting` | `.accept()` | Begins server-side handshake |
| `Incoming` | `Accepting` | `.accept_with(config)` | With custom `ServerConfig` |
| `Incoming` | (dropped) | `.refuse()` | Sends rejection |
| `Incoming` | (dropped) | `.ignore()` | No response sent |
| `Incoming` | `RetryError` | `.retry()` | Requires address validation |
| `Connecting` | `Connection` | `.await` | Polls handshake to completion |
| `Connecting` | `OutgoingZeroRttConnection` | `.into_0rtt()` | Attempts session resumption |
| `Accepting` | `Connection` | `.await` | Polls handshake to completion |
| `Accepting` | `IncomingZeroRttConnection` | `.into_0rtt()` | Always succeeds for incoming |
| `OutgoingZeroRttConnection` | `Connection` | `.handshake_completed()` | Returns `ZeroRttStatus` |

<!-- END GENERATED SECTION -->

## Registration with the Socket

After the QUIC handshake completes, every connection goes through `conn_from_noq_conn()` which:

1. Extracts the remote `EndpointId` from the TLS certificate
2. Extracts the ALPN protocol from the handshake data
3. Calls `register_connection()` on the socket to associate this connection with a `RemoteStateActor`
4. Runs the `after_handshake` hook, which may reject the connection

This registration step is what connects the QUIC connection to iroh's path management layer.

## Connection Capabilities

Once established, a `Connection` provides:
- **Bidirectional streams**: `open_bi()`, `accept_bi()`
- **Unidirectional streams**: `open_uni()`, `accept_uni()`
- **Datagrams**: `send_datagram()`, `read_datagram()`
- **Path info**: `remote_endpoint_id()`, `alpn()`, `remote_addr()`
- **Path watching**: `watch_best_path()` for monitoring path changes

## 0-RTT Security Model

0-RTT data is vulnerable to replay attacks. The security trade-off:
- **Outgoing 0-RTT** (`Connecting::into_0rtt`): Data may be replayed. Only use for idempotent operations. The remote may reject the 0-RTT attempt entirely.
- **Incoming 0-RTT** (`Accepting::into_0rtt`): Allows receiving 0-RTT data or sending 0.5-RTT data before the handshake completes. 0.5-RTT data is sent before TLS client authentication.
