# iroh

Iroh is a library to establish direct connectivity between endpoints.
It gives you an API for dialingy by public key. You say "connect to that
endpoint", and iroh finds and maintains the fastest connection for you,
regardless of where it is.

Under the hood iroh establishes peer-to-peer [QUIC] connections between
endpoints. The fastest route is a direct connection, so iroh tries to
[hole-punch] one whenever it can. If that fails it falls back to using
relay servers. Because it is built on QUIC, you get
authenticated encryption, concurrent streams with priorities, a datagram
transport, and no head-of-line blocking out of the box.

## How it works

An iroh endpoint is created and controlled by the [`Endpoint`]. Each endpoint
has a unique [`SecretKey`]; its [`PublicKey`] doubles as the endpoint's
identity, the [`EndpointId`]. Connections are encrypted and authenticated
against this key, so you always connect to exactly the peer you intended.

A connection is usually established with the help of a *relay server*. When an
endpoint is created it connects to the closest relay and designates it as its
*home relay*. Other endpoints reach it first through this relay, then both
sides attempt a direct connection using [QUIC Address Discovery][QAD] and hole
punching. Once the direct connection is up, the relay is no longer involved. If
hole punching does not succeed, traffic keeps flowing over the relay as a
fallback. Relay servers only ever forward encrypted traffic addressed by
[`EndpointId`]; they cannot read it.

Endpoints can also connect directly without a relay, as long as the accepting
endpoint is reachable at one of its addresses. You can supply a [`RelayUrl`],
direct addresses, or both.

## Example

This is an echo protocol: the accepting side copies back whatever it receives.
The full, commented version is in [`echo.rs`][echo-rs].

```rust,no_run
use iroh::{
    Endpoint,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};

/// Each protocol is identified by its ALPN, exchanged during the handshake.
const ALPN: &[u8] = b"iroh-example/echo/0";

#[tokio::main]
async fn main() -> n0_error::Result<()> {
    // The accepting side: bind an endpoint and route the ALPN to a handler.
    let endpoint = Endpoint::bind(presets::N0).await?;
    let router = Router::builder(endpoint).accept(ALPN, Echo).spawn();
    router.endpoint().online().await;
    let addr = router.endpoint().addr();

    // The connecting side: dial the accepting endpoint by its address.
    let endpoint = Endpoint::bind(presets::N0).await?;
    let conn = endpoint.connect(addr, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    send.write_all(b"Hello, world!").await?;
    send.finish()?;
    let response = recv.read_to_end(1000).await?;
    assert_eq!(&response, b"Hello, world!");

    conn.close(0u32.into(), b"bye!");
    endpoint.close().await;
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
        connection.closed().await;
        Ok(())
    }
}
```

More examples live in `iroh/examples`; run them with `cargo run --example
$NAME --features=examples`. Details for each are in the file itself.

## Compose protocols

Instead of writing your own, you can build on protocols that already exist on
top of iroh:

- [iroh-blobs] for [BLAKE3]-based content-addressed blob transfer, scaling from
  kilobytes to terabytes.
- [iroh-gossip] for publish-subscribe overlay networks that scale down to what
  an average phone can handle.
- and many more.

To use iroh from other languages, see [iroh-ffi].

## Structured events

The library uses [tracing] both for logging and for *structured events*.
Events differ from normal logging by convention:

- The [target] is prefixed with `iroh::_events::`, with `::`-separated names.
- There is **no message**; the unique target indicates the meaning.
- The [fields] carry exclusively structured data.
- The [Level] is always `DEBUG`.

This lets automated tooling process events through custom subscribers while
still producing distinct output under the default tracing formatters, and makes
them unlikely to conflict with real modules.

An application can subscribe to the `iroh::_events` target separately. With the
default file logging it is also easy to grep for all events:

```sh
rg 'events::[a-z_\-:]+' path/to/iroh/logs/iroh.YYYY-MM-DD-NN.log
```

When adding events, aim for a high signal-to-noise ratio and design them to be
extracted automatically. To keep them distinct from normal logging, write them
with the `event!()` macro:

```rust,ignore
event!(
    target: "iroh::_events::subject",
    Level::DEBUG,
    field = value,
);
```

[target]: https://docs.rs/tracing/latest/tracing/struct.Metadata.html#method.target
[fields]: https://docs.rs/tracing/latest/tracing/#recording-fields
[Level]: https://docs.rs/tracing/latest/tracing/struct.Level.html

## Building documentation

Building the documentation is only supported with `--all-features`. To also
document the cargo features required for certain APIs, pass the `iroh_docsrs`
cfg to rustdoc, which requires nightly Rust:

```sh
RUSTDOCFLAGS="--cfg iroh_docsrs" cargo +nightly doc --workspace --no-deps --all-features
```

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

[QUIC]: https://en.wikipedia.org/wiki/QUIC
[hole-punch]: https://en.wikipedia.org/wiki/Hole_punching_(networking)
[QAD]: https://www.ietf.org/archive/id/draft-ietf-quic-address-discovery-00.html
[BLAKE3]: https://github.com/BLAKE3-team/BLAKE3
[tracing]: https://docs.rs/tracing
[`Endpoint`]: https://docs.rs/iroh/latest/iroh/struct.Endpoint.html
[`SecretKey`]: https://docs.rs/iroh/latest/iroh/struct.SecretKey.html
[`PublicKey`]: https://docs.rs/iroh/latest/iroh/struct.PublicKey.html
[`EndpointId`]: https://docs.rs/iroh/latest/iroh/struct.EndpointId.html
[`RelayUrl`]: https://docs.rs/iroh/latest/iroh/struct.RelayUrl.html
[iroh-blobs]: https://github.com/n0-computer/iroh-blobs
[iroh-gossip]: https://github.com/n0-computer/iroh-gossip
[iroh-ffi]: https://github.com/n0-computer/iroh-ffi
[echo-rs]: /iroh/examples/echo.rs
