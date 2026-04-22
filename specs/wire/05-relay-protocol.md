# Relay Protocol

**Version:** 1.1

The relay protocol is iroh's custom packet forwarding protocol. It runs over WebSocket and allows endpoints to exchange encrypted QUIC packets through a relay server.

## Protocol Versioning

The relay protocol supports versioned negotiation. The client sends all supported protocol versions in the `Sec-WebSocket-Protocol` header during the WebSocket upgrade (e.g., `iroh-relay-v2,iroh-relay-v1`). The server selects the highest mutually-supported version and returns it in the response header. The current protocol version is **v2**.

| Version | Identifier | Notes |
|---------|-----------|-------|
| v1 | `iroh-relay-v1` | Original protocol |
| v2 | `iroh-relay-v2` | Replaced `Health` frame with `Status` frame |

Frames not valid for the negotiated protocol version MUST be treated as an error. Unknown frame types SHOULD be ignored for forward compatibility.

## Transport

The relay connection is established as follows:

1. The client opens an HTTPS connection to the relay server using standard TLS with X.509 certificates (the relay's own identity, not iroh Raw Public Keys).
2. The connection is upgraded to a WebSocket.
3. The handshake protocol authenticates the client (see [Handshake](#handshake) below).
4. Once authenticated, the connection enters the relay protocol phase for packet exchange.

All relay protocol frames are carried as binary WebSocket messages. Each WebSocket message contains exactly one relay protocol frame.

## Frame Format

Every frame begins with a frame type tag encoded as a QUIC VarInt ([RFC 9000 Section 16](https://www.rfc-editor.org/rfc/rfc9000#section-16)), followed by frame-specific payload.

```
+---------------+-------------------+
| Frame Type    | Payload           |
| (VarInt)      | (variable)        |
+---------------+-------------------+
```

For all currently defined frame types (0-12), the VarInt encoding is a single byte.

## Frame Types

| Value | Name | Direction | Version | Description |
|-------|------|-----------|---------|-------------|
| 0 | ServerChallenge | S → C | v1+ | Authentication challenge (handshake) |
| 1 | ClientAuth | C → S | v1+ | Authentication response (handshake) |
| 2 | ServerConfirmsAuth | S → C | v1+ | Authentication accepted (handshake) |
| 3 | ServerDeniesAuth | S → C | v1+ | Authentication denied (handshake) |
| 4 | ClientToRelayDatagram | C → S | v1+ | Single datagram to relay |
| 5 | ClientToRelayDatagramBatch | C → S | v1+ | Batched datagrams to relay |
| 6 | RelayToClientDatagram | S → C | v1+ | Single datagram from relay |
| 7 | RelayToClientDatagramBatch | S → C | v1+ | Batched datagrams from relay |
| 8 | EndpointGone | S → C | v1+ | Remote endpoint disconnected |
| 9 | Ping | Both | v1+ | Keepalive ping |
| 10 | Pong | Both | v1+ | Keepalive pong |
| 11 | Health | S → C | v1 only | Connection health status (deprecated) |
| 12 | Restarting | S → C | v1+ | Server restarting notification |
| 13 | Status | S → C | v2+ | Connection status (replaces Health) |

Direction: S = Server (relay), C = Client (endpoint).

## Handshake

The handshake protocol authenticates the client to the relay and establishes the client's Endpoint ID. There are two authentication mechanisms; the fast path is attempted first with fallback to the slow path.

### Fast Path: TLS Keying Material Export

This mechanism avoids an extra round-trip by leveraging TLS Keying Material Export ([RFC 5705](https://www.rfc-editor.org/rfc/rfc5705)).

1. The client exports 32 bytes of keying material from the TLS connection:
   - Label: `iroh-relay handshake v1`
   - Context: the client's public key bytes (32 bytes)
   - Output length: 32 bytes
2. The 32-byte export is split into two 16-byte halves:
   - First 16 bytes: the **message** to sign
   - Last 16 bytes: the **suffix** for verification
3. The client signs the message with its Ed25519 secret key.
4. The client sends its public key, signature, and suffix as an HTTP header (base64url-nopad encoded, postcard serialized) during the WebSocket upgrade request.
5. The server performs the same keying material export and verifies:
   - The suffix matches (confirming both sides derived the same material)
   - The signature is valid for the message and public key
6. If verification succeeds, the server sends `ServerConfirmsAuth` (frame type 2).

If the fast path fails (e.g., TLS proxy interference, browser environment, suffix mismatch), the server falls back to the slow path.

### Slow Path: Challenge-Response

1. The server generates a random 16-byte challenge and sends it as `ServerChallenge` (frame type 0):

```
+---------------+-----------------+
| 0x00          | challenge       |
| (1 byte)      | (postcard)      |
+---------------+-----------------+
```

The challenge is serialized using postcard and contains a `challenge` field of 16 random bytes.

2. The client derives a signing key using BLAKE3:

```
signing_key = blake3::derive_key("iroh-relay handshake v1 challenge signature", challenge)
```

This derivation provides domain separation, preventing a malicious relay from obtaining arbitrary signatures.

3. The client signs the 32-byte derived key and sends `ClientAuth` (frame type 1):

```
+---------------+-------------------------+
| 0x01          | ClientAuth              |
| (1 byte)      | (postcard)              |
+---------------+-------------------------+
```

The `ClientAuth` payload contains:
- `public_key`: the client's Ed25519 public key (32 bytes)
- `signature`: Ed25519 signature of the derived key (64 bytes)

4. The server verifies the signature against the derived key and the claimed public key.

5. The server sends either `ServerConfirmsAuth` (frame type 2) or `ServerDeniesAuth` (frame type 3):

```
ServerDeniesAuth contains:
- reason: UTF-8 string explaining the denial
```

### Serialization

All handshake frames use [postcard](https://docs.rs/postcard/) serialization for their payload (after the frame type tag). This is a compact binary format.

## Datagram Frames

### ClientToRelayDatagram (type 4)

A single datagram sent from a client to the relay for forwarding.

```
+-------+---------------------+------+-----------+
| 0x04  | dst_endpoint_id     | ECN  | contents  |
| (1B)  | (32 bytes)          | (1B) | (variable)|
+-------+---------------------+------+-----------+
```

### ClientToRelayDatagramBatch (type 5)

Multiple datagrams batched together (GSO-style), all destined for the same endpoint.

```
+-------+---------------------+------+--------------+-----------+
| 0x05  | dst_endpoint_id     | ECN  | segment_size | contents  |
| (1B)  | (32 bytes)          | (1B) | (2B, u16 BE) | (variable)|
+-------+---------------------+------+--------------+-----------+
```

The `contents` field contains multiple datagrams concatenated. Each datagram is `segment_size` bytes, except the last which MAY be shorter.

### RelayToClientDatagram (type 6)

A single datagram forwarded from the relay to a client.

```
+-------+---------------------+------+-----------+
| 0x06  | src_endpoint_id     | ECN  | contents  |
| (1B)  | (32 bytes)          | (1B) | (variable)|
+-------+---------------------+------+-----------+
```

### RelayToClientDatagramBatch (type 7)

Multiple datagrams batched together, all from the same source endpoint.

```
+-------+---------------------+------+--------------+-----------+
| 0x07  | src_endpoint_id     | ECN  | segment_size | contents  |
| (1B)  | (32 bytes)          | (1B) | (2B, u16 BE) | (variable)|
+-------+---------------------+------+--------------+-----------+
```

### ECN Byte

The ECN byte encodes the Explicit Congestion Notification codepoint:

| Value | Meaning |
|-------|---------|
| 0 | Not-ECT (no ECN) |
| 1 | ECT(1) |
| 2 | ECT(0) |
| 3 | CE (Congestion Experienced) |

### Segment Size

In batch frames, `segment_size` is a big-endian `u16` indicating the size of each individual datagram within the concatenated `contents`. The last segment MAY be shorter than `segment_size`. A `segment_size` of 0 SHOULD be treated as a single datagram (no batching).

## Control Frames

### EndpointGone (type 8)

Sent from server to client when a remote endpoint that previously sent packets to this client has disconnected from the relay.

```
+-------+---------------------+
| 0x08  | endpoint_id         |
| (1B)  | (32 bytes)          |
+-------+---------------------+
```

### Ping (type 9)

Keepalive probe. Either side MAY send a ping. The receiver MUST respond with a Pong containing the same payload.

```
+-------+----------+
| 0x09  | payload  |
| (1B)  | (8 bytes)|
+-------+----------+
```

### Pong (type 10)

Response to a Ping. The payload MUST match the payload of the Ping being replied to.

```
+-------+----------+
| 0x0A  | payload  |
| (1B)  | (8 bytes)|
+-------+----------+
```

### Health (type 11) — v1 only, deprecated

Server-to-client message indicating connection health issues. This frame is only valid in protocol v1. In v2+, use `Status` (type 13) instead.

```
+-------+-------------------+
| 0x0B  | problem           |
| (1B)  | (UTF-8, variable) |
+-------+-------------------+
```

The `problem` field is a UTF-8 string describing the issue. The default state is healthy; the server only sends this frame when a problem exists.

### Restarting (type 12)

Server-to-client notification that the relay server is restarting.

```
+-------+----------------+------------+
| 0x0C  | reconnect_in   | try_for    |
| (1B)  | (4B, u32 BE)   | (4B, u32 BE)|
+-------+----------------+------------+
```

- `reconnect_in`: Advisory duration in milliseconds before the client should attempt to reconnect. MAY be zero.
- `try_for`: Advisory duration in milliseconds for how long the client should keep attempting to reconnect before giving up.

### Status (type 13) — v2+

Server-to-client message indicating connection status. This replaces the `Health` frame from v1 with a binary-encoded, extensible enum. This frame MUST NOT be sent on v1 connections.

```
+-------+---------------+
| 0x0D  | status        |
| (1B)  | (1 byte)      |
+-------+---------------+
```

The `status` byte is a discriminant for the status type:

| Value | Status | Description |
|-------|--------|-------------|
| 0 | Healthy | Connection recovered from a previous problem |
| 1 | SameEndpointIdConnected | Another endpoint connected with the same Endpoint ID |
| 2+ | Unknown | Reserved for future use; implementations SHOULD handle gracefully |

The server sends `SameEndpointIdConnected` when a duplicate Endpoint ID connects, notifying the existing connection. The server sends `Healthy` when a previously problematic connection recovers.

## Connection Establishment Timeout

The relay server MUST enforce a timeout on connection establishment. The connection MUST be fully established (TLS handshake complete and WebSocket upgrade processed) within 30 seconds of the TCP connection being accepted. If the timeout expires, the server MUST close the connection.

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| MAX_PACKET_SIZE | 65,536 bytes (64 KiB) | Maximum datagram payload size |
| MAX_FRAME_SIZE | 1,048,576 bytes (1 MiB) | Maximum frame size (rate limiter minimum burst) |
| PING_INTERVAL | 15 seconds | Server-to-client ping frequency |
| PER_CLIENT_SEND_QUEUE_DEPTH | 512 | Maximum queued packets per client |

## Relay Routing

The relay server routes packets based solely on the destination Endpoint ID. It maintains a mapping from Endpoint ID to active WebSocket connection. When a datagram arrives:

1. Extract the `dst_endpoint_id` from the frame.
2. Look up the WebSocket connection for that Endpoint ID.
3. If found: rewrite the frame as `RelayToClient*`, replacing `dst_endpoint_id` with the sender's `src_endpoint_id`, and forward.
4. If not found: drop the packet and send `EndpointGone` to the sender.

The relay MUST NOT inspect, modify, or buffer the datagram `contents`. It is opaque, encrypted QUIC packet data.
