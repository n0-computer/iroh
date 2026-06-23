<h1 align="center">
<a href="https://iroh.computer">
<img alt="iroh" src="https://raw.githubusercontent.com/n0-computer/iroh/main/.img/iroh_wordmark.svg" width="100" />
</a>
</h1>

<h3 align="center">
less net work for networks
</h3>

[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square)](https://docs.rs/iroh/)
[![Crates.io](https://img.shields.io/crates/v/iroh.svg?style=flat-square)](https://crates.io/crates/iroh)
[![Chat](https://img.shields.io/discord/1161119546170687619?logo=discord&style=flat-square)](https://discord.com/invite/DpmJgtU7cW)
[![Youtube](https://img.shields.io/badge/YouTube-red?logo=youtube&logoColor=white&style=flat-square)](https://www.youtube.com/@n0computer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE)

<div align="center">
  <h3>
    <a href="https://iroh.computer/docs">
      Docs Site
    </a>
    <span> | </span>
    <a href="https://docs.rs/iroh">
      Rust Docs
    </a>
  </h3>
</div>
<br/>

Iroh is a Rust library to establish direct connections between endpoints.
It gives you an API for dialing by public key. You say "connect to that
endpoint", and iroh finds and maintains the best connection for you.

Under the hood iroh establishes peer-to-peer [QUIC] connections between
endpoints. The fastest route is a direct connection, so iroh tries to
[hole-punch] one whenever it can. If that fails it falls back to using
relay servers.

Because iroh is built on [QUIC], all connections are end-to-end encrypted and may
carry any number of concurrent streams. Dialing by public key also makes them mutually
authenticated, because each endpoint's public key is its TLS identity.

## Overview

An iroh endpoint is created and controlled by the [`Endpoint`]. Each endpoint
has a unique [`SecretKey`], whose public key is the endpoint's identity, the
[`EndpointId`]. Connections are authenticated against this key, which means an
[`EndpointId`] can't be impersonated.

A connection is usually established with the help of a *relay server*. When an
endpoint is created it connects to the closest relay and designates it as its
*home relay*. Other endpoints reach it first through this relay, then both
sides use QUIC NAT traversal to establish a direct connection. In the rare
cases where a direct connection is not possible, traffic keeps flowing over the
relay.

Relay servers only forward encrypted packets addressed to Endpoint IDs, they
cannot read any traffic between endpoints.

Endpoints can also connect directly without a relay, as long as the accepting
endpoint is directly reachable at one of its addresses.

To discover addressing information for an endpoint, iroh uses
[address lookup services]. With address lookup, you can connect to other
endpoints with only their [`EndpointId`]. Addressing information will then
be resolved on-demand.

The [`N0` preset] installs the DNS/Pkarr address lookup service, which uses
servers hosted by [n0] to provide global lookup for endpoints.

## Example

This is an echo protocol: the accepting side copies back whatever it receives.
The full, commented version is in [`echo.rs`](examples/echo.rs).

```rust
use iroh::{
    Endpoint,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};

/// Each protocol is identified by its ALPN, exchanged during the handshake.
const ALPN: &[u8] = b"iroh-example/echo/0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The accepting side: bind an endpoint and route the ALPN to a handler.
    let endpoint = Endpoint::bind(presets::N0).await?;
    let router = Router::builder(endpoint.clone()).accept(ALPN, Echo).spawn();
    endpoint.online().await;
    // Get the endpoint's address so that we can connect to it.
    let addr = endpoint.addr();

    // The connecting side: dial the accepting endpoint by its address.
    {
        let other_endpoint = Endpoint::bind(presets::N0).await?;

        let conn = other_endpoint.connect(addr, ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(b"Hello, world!").await?;
        send.finish()?;
        let response = recv.read_to_end(1000).await?;
        assert_eq!(&response, b"Hello, world!");
        conn.close(0u32.into(), b"bye!");

        other_endpoint.close().await;
    }

    router.shutdown().await?;
    Ok(())
}

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        // Echo bytes back until the sender signals the end of data.
        tokio::io::copy(&mut recv, &mut send).await?;
        send.finish()?;
        // Wait until the other endpoint closes the connection.
        connection.closed().await;
        Ok(())
    }
}
```

More examples live in [`iroh/examples`](examples). Run them with
`cargo run --example NAME`. Details for each are in the file itself.

## Compose protocols

Instead of writing your own, you can build on protocols that already exist on
top of iroh:

- [iroh-blobs] for [BLAKE3]-based content-addressed blob transfer, scaling from
  kilobytes to terabytes.
- [iroh-gossip] for publish-subscribe overlay networks that scale down to what
  an average phone can handle.
- and many more.

To use iroh from other languages, see [iroh-ffi].

## Development

For notes on iroh's structured events and how to build the documentation, see
[DEVELOPMENT.md](DEVELOPMENT.md).

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.

### Contribution

See [CONTRIBUTING.md](https://github.com/n0-computer/iroh/blob/main/CONTRIBUTING.md)
for how to get involved.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

[QUIC]: https://en.wikipedia.org/wiki/QUIC
[hole-punch]: https://en.wikipedia.org/wiki/Hole_punching_(networking)
[BLAKE3]: https://github.com/BLAKE3-team/BLAKE3
[`Endpoint`]: https://docs.rs/iroh/latest/iroh/struct.Endpoint.html
[`SecretKey`]: https://docs.rs/iroh/latest/iroh/struct.SecretKey.html
[`EndpointId`]: https://docs.rs/iroh/latest/iroh/struct.EndpointId.html
[address lookup services]: https://docs.rs/iroh/latest/iroh/address_lookup/index.html
[`N0` preset]: https://docs.rs/iroh/latest/iroh/endpoint/presets/struct.N0.html
[iroh-blobs]: https://github.com/n0-computer/iroh-blobs
[iroh-gossip]: https://github.com/n0-computer/iroh-gossip
[iroh-ffi]: https://github.com/n0-computer/iroh-ffi
[n0]: https://n0.computer
