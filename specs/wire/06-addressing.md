# Addressing

**Version:** 1.0

This section specifies the encoding formats for iroh addressing: the EndpointAddr structure, DNS record format, Pkarr signed packets, and custom transport addresses.

## EndpointAddr

An `EndpointAddr` combines an Endpoint ID with a set of transport addresses. It is the primary structure used to describe how to reach an endpoint.

### Binary Encoding

EndpointAddr uses [postcard](https://docs.rs/postcard/) binary serialization. The structure is:

```
EndpointAddr {
    id:    EndpointId          // 32 bytes, Ed25519 public key
    addrs: Set<TransportAddr>  // postcard-encoded sorted set
}
```

### TransportAddr Variants

TransportAddr is a tagged enum. In postcard encoding, each variant is prefixed by its variant index:

| Variant Index | Type | Payload |
|---------------|------|---------|
| 0 | Relay | RelayUrl (postcard-encoded string) |
| 1 | Ip | SocketAddr (postcard-encoded) |
| 2 | Custom | CustomAddr (see below) |

The set is serialized as a length-prefixed sequence of TransportAddr values, sorted in canonical order.

## CustomAddr

A custom transport address for non-IP transports.

### Binary Encoding

```
+-------------------+-------------------+
| transport_id      | data              |
| (8 bytes, LE u64) | (variable bytes)  |
+-------------------+-------------------+
```

Minimum valid length: 8 bytes (transport ID only, empty data).

### String Encoding

Format: `{id}_{data}` where:
- `{id}` is the transport ID as lowercase hexadecimal (no `0x` prefix, no leading zeros)
- `{data}` is the address bytes as lowercase hexadecimal

Examples:
- `20_ab01cd02...` (Test transport, ID 0x20)
- `544f52_ab01cd02...` (Tor transport, ID 0x544F52)
- `0_` (transport ID 0, empty data)

### Registered Transport IDs

| ID Range | Transport | Address Format |
|----------|-----------|----------------|
| `0x00`-`0x1F` | Reserved | — |
| `0x20` | Test | Ed25519 public key (32 bytes) |
| `0x544F52` | Tor | Ed25519 public key (32 bytes) |
| `0x424C45` | BLE | Bluetooth MAC address (6 bytes) |

## DNS Record Format

Endpoint addressing information is published as DNS TXT records for address lookup.

### Query Name

```
_iroh.{z32-endpoint-id}.{origin-domain}
```

Where:
- `_iroh` is a fixed record name prefix
- `{z32-endpoint-id}` is the Endpoint ID encoded in z-base-32 (52 characters)
- `{origin-domain}` is the DNS origin domain (e.g., `iroh.link`)

### TXT Record Format

The TXT record contains key-value pairs encoding addressing information:

```
relay={relay_url}
```

Where `{relay_url}` is the full URL of the endpoint's home relay server (e.g., `https://use1-1.relay.iroh.network./`).

Additional address types MAY be encoded as additional TXT record entries.

### z-base-32 Encoding

The Endpoint ID in DNS queries uses z-base-32 encoding as defined in the [z-base-32 specification](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt). This encoding produces 52-character strings from the 32-byte Endpoint ID.

## Pkarr Signed Packets

Pkarr ([Public Key Addressable Resource Records](https://github.com/Nuhvi/pkarr/blob/main/design/base.md)) is used to publish and resolve endpoint addressing information.

### Signed Packet Structure

```
+--------------------+--------------------+--------------------+--------------------+
| public_key         | signature          | timestamp          | dns_packet         |
| (32 bytes)         | (64 bytes)         | (8 bytes, BE u64)  | (< 1000 bytes)     |
+--------------------+--------------------+--------------------+--------------------+
```

- `public_key`: The endpoint's Ed25519 public key (same as Endpoint ID)
- `signature`: Ed25519 signature over the timestamp and DNS packet
- `timestamp`: Microseconds since the Unix epoch (big-endian u64)
- `dns_packet`: Standard DNS packet containing address records

### DNS Packet Contents

The DNS packet within a Pkarr signed packet contains TXT records with the same format as the DNS records described above (`relay={url}`, etc.).

### Publication

Endpoints publish their Pkarr signed packets via HTTP:

- **Publish**: `PUT {pkarr_relay_url}/{z32-public-key}`
- **Resolve**: `GET {pkarr_relay_url}/{z32-public-key}`

The request/response body is the raw signed packet bytes.

### Publication Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Default TTL | 30 seconds | TTL for DNS records within the packet |
| Republish interval | 5 minutes | Frequency of republishing even if unchanged |

### Address Filtering

By default, implementations SHOULD publish only relay URLs in Pkarr records, not direct IP addresses. This prevents leaking endpoint IP addresses to public infrastructure. The address filter MAY be configured to include direct addresses when appropriate.

### Mainline DHT

Pkarr signed packets MAY also be published to the Mainline DHT using BEP-0044 (mutable data). This provides a fully decentralized resolution path but is OPTIONAL.
