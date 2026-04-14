# Relay over WebTransport (QUIC)

## Status

Implemented on `relay-h3-wt` branch. All 65 tests passing.

## Architecture

```
                  WebSocket path              WebTransport path
                  --------------              -----------------
  TCP                                    UDP (QUIC via noq)
   |                                          |
  TLS (rustls)                           QUIC TLS 1.3 (built-in)
   |                                          |
  HTTP/1.1 (hyper)                       WebTransport (web-transport-proto)
   |                                          |
  WebSocket upgrade                      CONNECT + WT bidi stream
   |                                          |
  WsBytesFramed                          WtBytesFramed (varint-prefixed)
   |                                          |
  Relay protocol (unchanged)             Relay protocol (unchanged)
```

Both transports share the same `Clients` registry, `AccessConfig`, and relay
handshake (`handshake::serverside` / `handshake::clientside`). A WebSocket
client can relay to a WebTransport client and vice versa.

## Protocol flow (2 RTTs to first relay byte)

```
RTT 1: QUIC handshake (TLS 1.3)
        Client sends Settings (concurrent, uni stream)
        Server sends Settings (concurrent, uni stream)

RTT 2: Client sends CONNECT with keying material auth header
        Server validates auth from header (0 extra RTTs)
        Server responds 200, opens WT data bidi stream
        Relay handshake completes (ServerConfirmsAuth)
```

For comparison, WebSocket takes 3-4 RTTs (TCP + TLS + WS upgrade + relay auth).

## Key design decisions

- **WebTransport over QUIC** via `web-transport-proto`: no h3 crate needed,
  browser-compatible, simpler than RFC 9220 extended CONNECT.
- **Varint-length-prefixed messages** on the WT data stream: QUIC streams are
  byte-oriented, the relay protocol needs message framing. Uses QUIC varints
  for browser compatibility.
- **TLS keying material export**: `noq::Connection::export_keying_material`
  provides the same RFC 5705 mechanism as the WS path, eliminating the
  challenge-response RTT.
- **Shared Clients + AccessConfig via Arc**: both WS and WT servers register
  clients in the same pool with the same access control.
- **0-RTT is not used**: the WebTransport spec prohibits CONNECT in 0-RTT
  packets. However, QUIC 0-RTT could carry client Settings in the future.

## Dependencies

- `web-transport-proto = "0.6.0"`: WebTransport CONNECT/Settings/Frame encoding
- `noq`: QUIC transport (SendStream/RecvStream implement AsyncRead/AsyncWrite)
- No h3 crate, no adapter crate

## Files

- `iroh-relay/src/protos/h3_streams.rs`: `WtBytesFramed` (varint Stream/Sink)
- `iroh-relay/src/server/h3_server.rs`: WT relay server
- `iroh-relay/src/client/h3_conn.rs`: WT relay client
- `iroh-relay/src/client/conn.rs`: `ConnInner` enum (Ws/WsBrowser/Wt)
