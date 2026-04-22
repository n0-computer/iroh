# Address Lookup

**Version:** 1.1

Address lookup is the process of resolving an Endpoint ID to the transport addresses needed to establish a connection. It is a pluggable system — different lookup implementations can be used depending on the deployment scenario.

## The Problem

To connect to a remote endpoint, iroh needs at least one transport address in addition to the Endpoint ID — typically a relay URL or a direct IP address. These addresses can change over time as endpoints move between networks, change relay servers, or obtain new IP addresses.

Address lookup bridges the gap between a stable identity (the Endpoint ID) and the ephemeral network addresses where an endpoint can currently be reached.

## Lookup Implementations

### DNS Address Lookup

The primary lookup implementation resolves Endpoint IDs through DNS. Endpoints publish their addressing information as DNS TXT records using the Pkarr protocol (see below), and connecting endpoints query those records to obtain current addresses.

The DNS query format is:

```
_iroh.{z32-endpoint-id}.{origin-domain}
```

Where:
- `_iroh` is a fixed record name prefix
- `{z32-endpoint-id}` is the Endpoint ID encoded in z-base-32
- `{origin-domain}` is the DNS origin (e.g., `iroh.link`)

The response contains TXT records with addressing information, such as:

```
relay=https://relay.example.com
```

DNS lookups use staggered queries with increasing delays (200ms, 300ms, 600ms, 1000ms, 2000ms, 3000ms) to balance speed against reliability. The first successful response is used.

### Pkarr (Public Key Addressable Resource Records)

Pkarr is the underlying mechanism for publishing endpoint addresses. It allows endpoints to publish signed DNS resource records keyed by their Ed25519 public key. A Pkarr signed packet contains:

- The endpoint's public key (32 bytes)
- An Ed25519 signature (64 bytes)
- A timestamp (8 bytes)
- A DNS packet containing the addressing records

Endpoints publish their Pkarr records to a relay service via HTTP PUT and resolve them via HTTP GET. Records can also be published directly to the Mainline DHT using BEP-0044.

By default, iroh publishes **only relay URLs** in Pkarr records, not direct IP addresses. This is a privacy-preserving default — publishing IP addresses to a public service would leak location information. Applications that want to publish direct addresses can configure a different address filter.

Records are republished every 5 minutes to keep them fresh, with a default TTL of 30 seconds.

### mDNS (Multicast DNS)

mDNS provides address lookup on the local network without requiring any external infrastructure. Endpoints advertise and discover each other using multicast DNS on the local network segment. This is useful for scenarios where two endpoints are on the same LAN and can connect directly without relay servers.

### Memory Lookup

The memory lookup is an in-process address book that provides addresses supplied directly by the application. This is useful when addressing information is obtained out-of-band — for example, exchanged via a QR code, chat message, or other application-specific channel.

## Address Publishing

Address lookup has two sides: **publishing** and **resolving**. An endpoint publishes its own addressing information so that other endpoints can find it, and resolves other endpoints' IDs to connect to them.

Publishing is continuous: the endpoint monitors its own addressing information (relay URL, direct addresses) and republishes whenever it changes. This ensures that remote endpoints always have up-to-date addressing information.

## Address Filtering

When publishing addresses, endpoints apply an **address filter** that controls which address types are included. The default filter publishes only relay URLs, which provides reachability without leaking IP addresses to public infrastructure. Applications can configure the filter to include direct IP addresses when appropriate for their use case.

IPv6 addresses with the `deprecated` flag (as defined in [RFC 4862](https://www.rfc-editor.org/rfc/rfc4862)) are automatically excluded from published addresses, regardless of filter configuration. Deprecated addresses are being phased out by the operating system and should not be used for new connections.

## Error Handling

When multiple lookup services are configured, a failure in one service does not abort the overall lookup. Each service runs to completion independently, and results are merged. Only if all services fail or return no results is the lookup considered failed. This ensures that a transient error in one service (e.g., DNS timeout) does not prevent results from another service (e.g., mDNS) from being used.
