# Relay Handshake Protocol

The relay handshake authenticates clients connecting to relay servers. Its purpose:
1. Inform the relay of the client's `EndpointId`
2. Verify the client owns the secret key for that `EndpointId` (authentication)
3. Optionally check authorization (if the relay restricts access)

## Authentication Methods

There are two authentication paths, selected based on TLS capabilities:

<!-- BEGIN GENERATED SECTION
Source: iroh-relay/src/protos/handshake.rs
Prompt: Read the module doc comment, the frame types (ServerChallenge, ClientAuth,
        KeyMaterialClientAuth, ServerConfirmsAuth, ServerDeniesAuth), and any
        client/server handshake functions. Generate a sequenceDiagram showing both
        the fast path (TLS keying material) and the fallback path (challenge-response).
-->

```mermaid
sequenceDiagram
    participant Client
    participant Relay as Relay Server

    Note over Client,Relay: WebSocket connection established

    alt Fast Path (TLS Keying Material)
        Note over Client: Extract TLS keying material (RFC 5705)
        Client->>Relay: KeyMaterialClientAuth {public_key, signature, key_material_suffix}
        alt Verification succeeds
            Relay->>Client: ServerConfirmsAuth
        else Verification fails (proxy, browser, mismatch)
            Note over Relay: Fall through to challenge path
            Relay->>Client: ServerChallenge {challenge: [u8; 16]}
            Client->>Relay: ClientAuth {public_key, signature}
            alt Challenge verification succeeds
                Relay->>Client: ServerConfirmsAuth
            else Challenge verification fails
                Relay->>Client: ServerDeniesAuth {reason}
            end
        end
    else Fallback Path (Challenge-Response)
        Note over Client: No TLS keying material available
        Relay->>Client: ServerChallenge {challenge: [u8; 16]}
        Client->>Relay: ClientAuth {public_key, signature}
        alt Verification succeeds
            Relay->>Client: ServerConfirmsAuth
        else Verification fails
            Relay->>Client: ServerDeniesAuth {reason}
        end
    end

    Note over Client,Relay: Authenticated — ready to send/recv datagrams
```

### Frame Types

| Frame | Direction | Purpose |
|-------|-----------|---------|
| `KeyMaterialClientAuth` | Client -> Relay | Fast auth: signature of TLS-exported keying material |
| `ServerChallenge` | Relay -> Client | Random 16-byte challenge for the client to sign |
| `ClientAuth` | Client -> Relay | Signature of the challenge + `EndpointId` |
| `ServerConfirmsAuth` | Relay -> Client | Authentication succeeded |
| `ServerDeniesAuth` | Relay -> Client | Authentication failed, with reason |

### Domain Separation

| Constant | Value | Used For |
|----------|-------|----------|
| `DOMAIN_SEP_CHALLENGE` | `"iroh-relay handshake v1 challenge signature"` | Challenge-response signatures |
| `DOMAIN_SEP_TLS_EXPORT_LABEL` | `b"iroh-relay handshake v1"` | TLS keying material export |

<!-- END GENERATED SECTION -->

## Why Two Paths?

The **fast path** (TLS keying material) saves a full round trip because no challenge needs
to be sent. It works by having the client sign material derived from the TLS session via
[RFC 5705](https://datatracker.ietf.org/doc/html/rfc5705), similar to
[Concealed HTTP Auth (RFC 9729)](https://datatracker.ietf.org/doc/rfc9729/).

However, it doesn't always work:
- **Browsers** don't expose the TLS keying material export API
- **HTTPS proxies** may interfere with the TLS session, making the extracted material mismatch
- Some TLS implementations may not support this feature

The **fallback path** (challenge-response) always works but costs an extra round trip.
