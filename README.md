<h1 align="center"><a href="https://iroh.computer"><img alt="iroh" src="./.img/iroh_wordmark.svg" width="100" /></a></h1>

<h3 align="center">
less net work for networks
</h3>

[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square)](https://docs.rs/iroh/)
[![Crates.io](https://img.shields.io/crates/v/iroh.svg?style=flat-square)](https://crates.io/crates/iroh)
[![downloads](https://img.shields.io/crates/d/iroh.svg?style=flat-square)](https://crates.io/crates/iroh)
[![Chat](https://img.shields.io/discord/1161119546170687619?logo=discord&style=flat-square)](https://discord.com/invite/DpmJgtU7cW)
[![Youtube](https://img.shields.io/badge/YouTube-red?logo=youtube&logoColor=white&style=flat-square)](https://www.youtube.com/@n0computer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE)
[![CI](https://img.shields.io/github/actions/workflow/status/n0-computer/iroh/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/n0-computer/iroh/actions/workflows/ci.yml)

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

## What is iroh?

Iroh gives you an API for dialing by public key.
You say “connect to that phone”, iroh will find & maintain the fastest connection for you, regardless of where it is.

### Hole-punching

The fastest route is a direct connection, so if necessary, iroh tries to hole-punch.
Should this fail, it can fall back to an open ecosystem of public relay servers.
To ensure these connections are as fast as possible, we [continuously measure iroh][iroh-perf].

### Built on [QUIC]

Iroh uses [Quinn] to establish [QUIC] connections between nodes.
This way you get authenticated encryption, concurrent streams with stream priorities, a datagram transport and avoid head-of-line-blocking out of the box.

## Compose Protocols

Use pre-existing protocols built on iroh instead of writing your own:
- [iroh-blobs] for [BLAKE3]-based content-addressed blob transfer scaling from kilobytes to terabytes
- [iroh-gossip] for establishing publish-subscribe overlay networks that scale, requiring only resources that your average phone can handle
- [iroh-docs] for an eventually-consistent key-value store of [iroh-blobs] blobs
- [iroh-willow] for an (in-construction) implementation of the [willow protocol]

## Getting Started

### Rust Library

It's easiest to use iroh from rust.
Install it using `cargo add iroh`, then on the connecting side:

```rs
const ALPN: &[u8] = b"iroh-example/echo/0";

let endpoint = Endpoint::builder().discovery_n0().bind().await?;

// Open a connection to the accepting node
let conn = endpoint.connect(addr, ALPN).await?;

// Open a bidirectional QUIC stream
let (mut send, mut recv) = conn.open_bi().await?;

// Send some data to be echoed
send.write_all(b"Hello, world!").await?;
send.finish()?;

// Receive the echo
let response = recv.read_to_end(1000).await?;
assert_eq!(&response, b"Hello, world!");

// Close the endpoint and all its connections
endpoint.close().await;
```

And on the accepting side:
```rs
let endpoint = Endpoint::builder().discovery_n0().bind().await?;

let router = Router::builder(endpoint)
    .accept(ALPN.to_vec(), Arc::new(Echo))
    .spawn()
    .await?;

// The protocol definition:
#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    fn accept(&self, connection: Connection) -> BoxedFuture<Result<()>> {
        Box::pin(async move {
            let (mut send, mut recv) = connection.accept_bi().await?;

            // Echo any bytes received back directly.
            let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;

            send.finish()?;
            connection.closed().await;

            Ok(())
        })
    }
}
```

The full example code with more comments can be found at [`echo.rs`][echo-rs].

Or use one of the pre-existing protocols, e.g. [iroh-blobs] or [iroh-gossip].

### Other Languages

If you want to use iroh from other languages, make sure to check out [iroh-ffi], the repository for FFI bindings.

### Links

- [Introducing Iroh (video)][iroh-yt-video]
- [Iroh Documentation][docs]
- [Iroh Examples]
- [Iroh Experiments]

## Repository Structure

This repository contains a workspace of crates:
- `iroh`: The core library for hole-punching & communicating with relays.
- `iroh-relay`: The relay server implementation. This is the code we run in production (and you can, too!).
- `iroh-base`: Common types like `Hash`, key types or `RelayUrl`.
- `iroh-dns-server`: DNS server implementation powering the `n0_discovery` for NodeIds, running at dns.iroh.link.
- `iroh-net-report`: Analyzes your host's networking ability & NAT.

## License

Copyright 2024 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[QUIC]: https://en.wikipedia.org/wiki/QUIC
[BLAKE3]: https://github.com/BLAKE3-team/BLAKE3
[Quinn]: https://github.com/quinn-rs/quinn
[iroh-blobs]: https://github.com/n0-computer/iroh-blobs
[iroh-gossip]: https://github.com/n0-computer/iroh-gossip
[iroh-docs]: https://github.com/n0-computer/iroh-docs
[iroh-willow]: https://github.com/n0-computer/iroh-willow
[iroh-doctor]: https://github.com/n0-computer/iroh-doctor
[willow protocol]: https://willowprotocol.org
[iroh-ffi]: https://github.com/n0-computer/iroh-ffi
[iroh-yt-video]: https://www.youtube.com/watch?v=RwAt36Xe3UI_
[Iroh Examples]: https://github.com/n0-computer/iroh-examples
[Iroh Experiments]: https://github.com/n0-computer/iroh-experiments
[echo-rs]: /iroh/examples/echo.rs
[iroh-perf]: https://perf.iroh.computer
[docs]: https://iroh.computer/docs
