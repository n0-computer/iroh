# Iroh Relay

Iroh's relay is a feature within [iroh], a peer-to-peer networking system
designed to facilitate direct, encrypted connections between devices. Iroh aims
to simplify decentralized communication by automatically handling connections
through "relays" when direct connections aren't immediately possible. The relay
server helps establish connections by temporarily routing encrypted traffic
until a direct, P2P connection is feasible. Once this direct path is set up,
the relay server steps back, and the data flows directly between devices. This
approach allows Iroh to maintain a secure, low-latency connection, even in
challenging network situations.

This crate provides a complete setup for creating and interacting with iroh
relays, including:
- Relay Protocol: The protocol used to communicate between relay servers and
  clients
- Relay Server: A fully-fledged iroh-relay server over HTTP or HTTPS.
  Optionally will also expose a stun endpoint and metrics.
- Relay Client: A client for establishing connections to the relay.
- Server Binary: A CLI for running your own relay server. It can be configured
  to also offer STUN support and expose metrics.


Used in [iroh], created with love by the [n0 team](https://n0.computer/).

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

[iroh]: https://github.com/n0-computer/iroh
