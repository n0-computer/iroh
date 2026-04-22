# Relays

**Version:** 1.1

Relay servers are publicly-reachable infrastructure that ensure any two iroh endpoints can always communicate, regardless of NAT, firewall, or network topology.

## Purpose

Many endpoints sit behind NATs or firewalls that prevent direct incoming connections. Relay servers solve this by acting as rendezvous points: both endpoints maintain outbound connections to relay servers, and the relay forwards packets between them.

Relay servers handle only encrypted QUIC packets. They route packets based on the destination Endpoint ID without being able to read their contents. The end-to-end encryption between iroh endpoints is independent of the relay server's TLS — the relay is a transport mechanism, not a trusted intermediary.

## Home Relay

When an iroh endpoint starts, it performs latency probes to all known relay servers and selects the one with the lowest latency as its **home relay**. This relay is the primary rendezvous point where other endpoints will attempt to reach it.

The home relay selection process:
1. The endpoint runs network probes (HTTPS latency, QAD IPv4, QAD IPv6) to each known relay server.
2. The relay with the lowest observed latency becomes the home relay.
3. The endpoint maintains a persistent connection to its home relay.
4. If network conditions change, the endpoint re-evaluates and may switch to a different home relay.

An endpoint advertises its home relay URL as part of its addressing information (see [Addressing](04-addressing.md) and [Address Lookup](05-address-lookup.md)), so that remote endpoints know where to find it.

## Relay Connection

The connection between an endpoint and a relay server is established as follows:

1. The endpoint opens an HTTP/1.1 connection to the relay server over TLS (using standard X.509 certificates for the relay's identity).
2. The connection is upgraded to a WebSocket.
3. The endpoint authenticates to the relay using its Ed25519 key pair, proving ownership of its Endpoint ID.
4. The relay registers the endpoint and begins forwarding packets addressed to its Endpoint ID.

Once connected, the endpoint can send packets to any other endpoint connected to the same relay by specifying the destination Endpoint ID. The relay looks up the destination's connection and forwards the packet.

## Packet Forwarding

When endpoint A wants to send a packet to endpoint B via a relay:

1. A sends the QUIC packet to the relay, tagged with B's Endpoint ID.
2. The relay looks up B's connection.
3. If B is connected, the relay forwards the packet to B, tagged with A's Endpoint ID.
4. If B is not connected to this relay, the packet is dropped and A is notified that B is gone.

The relay does not buffer packets — if the destination is not currently connected, the packet is lost. This is acceptable because QUIC handles retransmission at the transport layer.

## QAD Service

Relay servers also provide a QUIC Address Discovery (QAD) service. This is a separate QUIC endpoint on the relay server that helps iroh endpoints discover their public IP address and port as observed from the relay's perspective. This information is critical for NAT traversal (see [Holepunching](07-holepunching.md)).

The QAD service uses the ALPN `/iroh-qad/0` and implements the QUIC Address Discovery draft. When an endpoint connects, the relay observes the endpoint's public IP:port and reports it back via QUIC's observed address mechanism.

## Multiple Relays

An endpoint may be connected to multiple relay servers simultaneously, but only one is designated as the home relay. Connections to non-home relays are established as needed — for example, when communicating with a peer whose home relay is different from the local endpoint's home relay.

The relay connection is kept alive with periodic pings (every 15 seconds). If a relay connection drops, the endpoint reconnects automatically.

## Health Checking After Network Changes

When a major network change is detected, the endpoint sends an immediate health check ping to all active relay connections rather than waiting for the next scheduled ping. The health check uses an RTT-based timeout of 3x the last observed RTT (clamped between 500ms and 5s). This allows broken relay connections to be detected and recovered within ~500ms–1s instead of waiting up to 15s for the next scheduled ping.
