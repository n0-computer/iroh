# Iroh Specification v1.0 — API Reference

This specification describes how iroh works at a conceptual level. It is intended for power users who want to understand iroh's design and behavior without reading the source code.

For the low-level wire protocol specification, see [../wire/](../wire/README.md).

**Version:** 1.0

## Table of Contents

1. [Overview](01-overview.md) — What iroh is, design philosophy, and building blocks
2. [Endpoints](02-endpoints.md) — Endpoint setup, identity, home relay selection, and authentication
3. [Connections](03-connections.md) — QUIC connections, streams, and datagrams
4. [Addressing](04-addressing.md) — Endpoint addresses and transport address types
5. [Address Lookup](05-address-lookup.md) — Resolving endpoint IDs to dialable addresses
6. [Relays](06-relays.md) — Relay servers, home relay selection, and packet forwarding
7. [Holepunching](07-holepunching.md) — NAT traversal and direct connection upgrade
8. [Transports](08-transports.md) — UDP, relay, custom transports, and multipath
