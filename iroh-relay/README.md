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

## Local testing

Advice for testing your application that uses `iroh` with a locally running `iroh-relay` server

### dev mode
When running the relay server using the `--dev` flag, you will:
- only run the server over http, not https
- will NOT run the QUIC endpoint that enables QUIC address discovery

The relay can be contacted at "http://localhost:3340".

Both https and QUIC address discovery require TLS certificates. It's possible to run QUIC address discovery using locally generated TLS certificates, but it takes a few extra steps and so, is disabled by default for now.

### dev mode with QUIC address discovery

So you want to test out QUIC address discovery locally?

In order to do that you need TLS certificates.

The easiest get that is to generate self-signed certificates using `rcgen`
  - get rcgen (`git clone https://github.com/rustls/rcgen`)
  - cd to the `rcgen` directory
  - generate local certs using `cargo run -- -o path/to/certs`

Next, add the certificate paths to your iroh-relay config, here is an example of a config.toml file that will enable quic address discovery.
```toml
enable_quic_addr_discovery = true

[tls]
cert_mode = "Manual"
manual_cert_path = "/path/to/certs/cert.pem"
manual_key_path = "/path/to/certs/cert.key.pem"
```

Then run the server with the `--dev` flag, like you would when normally testing locally:
`cargo run --bin iroh-relay -- --config-path=/path/to/config.toml --dev`

The relay server will run over http on port 3340, as it does using the `--dev` flag, but it will also run a QUIC server on port 7824.

The relay will use the configured TLS certificates for the QUIC connection, but use http (rather than https) for the server.

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
