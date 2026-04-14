# Addressing

**Version:** 1.0

This section describes how iroh endpoints are addressed on the network.

## Endpoint Address

An **Endpoint Address** (`EndpointAddr`) combines an Endpoint ID with a set of transport addresses that describe how to reach the endpoint on the network:

```
EndpointAddr {
    id:    EndpointId          // Ed25519 public key (32 bytes)
    addrs: Set<TransportAddr>  // zero or more transport addresses
}
```

The Endpoint ID is always required. The set of transport addresses may be empty if an address lookup service is configured to resolve the Endpoint ID at connection time (see [Address Lookup](address-lookup.md)).

## Transport Address Types

A transport address describes a single network path to an endpoint. There are three types:

### Relay

A relay transport address is the URL of a relay server through which the endpoint is reachable:

```
TransportAddr::Relay(RelayUrl)
```

The relay URL identifies the endpoint's home relay server. When connecting via a relay, the endpoint is identified by its Endpoint ID — the relay forwards packets to the correct destination based on this key.

In practice, an endpoint has zero or one relay address. Having a relay address is the most common and reliable way to reach an endpoint, since relay servers are publicly accessible and relay connections always succeed regardless of NAT or firewall configuration.

### IP

An IP transport address is a direct socket address (IPv4 or IPv6 with port):

```
TransportAddr::Ip(SocketAddr)
```

Direct IP addresses allow connections without a relay server, but only work when there is a routable path between the two endpoints. In many network configurations, direct addresses are only useful after hole punching has established a NAT binding.

### Custom

A custom transport address represents a non-IP transport such as Tor or Bluetooth:

```
TransportAddr::Custom(CustomAddr {
    id:   u64    // transport identifier
    data: bytes  // opaque address data
})
```

The transport identifier is a freely-chosen `u64` that identifies the transport type. A registry of well-known transport IDs is maintained in the iroh repository. The address data is opaque and interpreted only by the corresponding transport implementation.

**String encoding:** `{hex_id}_{hex_data}` (e.g., `544f52_ab01cd02...` for a Tor address)

**Binary encoding:** 8-byte little-endian `u64` transport ID followed by raw address bytes.

### Registered Custom Transport IDs

| ID | Transport | Address Format |
|----|-----------|----------------|
| `0x00`-`0x1F` | Reserved | — |
| `0x20` | Test | Ed25519 public key (32 bytes) |
| `0x544F52` | Tor | Ed25519 public key (32 bytes) |
| `0x424C45` | BLE | Bluetooth MAC address (6 bytes) |
