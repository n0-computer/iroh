<img alt="iroh" src="./.img/iroh_wordmark.svg" width="100" />
https://iroh.computer

Bytes, Distributed.

<div align="center">
  <!-- Crates version -->
  <a href="https://crates.io/crates/iroh">
    <img src="https://img.shields.io/crates/v/iroh.svg?style=flat-square"
    alt="Crates.io version" />
  </a>
  <!-- Downloads -->
  <a href="https://crates.io/crates/iroh">
    <img src="https://img.shields.io/crates/d/iroh.svg?style=flat-square"
      alt="Download" />
  </a>
  <!-- docs.rs docs -->
  <a href="https://docs.rs/iroh">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square"
      alt="docs.rs docs" />
  </a>
</div>

<div align="center">
  <h3>
    <a href="https://iroh.computer/docs">
      Docs Site
    </a>
    <span> | </span>
    <a href="https://docs.rs/iroh">
      Rust Docs
    </a>
    <span> | </span>
    <a href="https://github.com/n0-computer/iroh/releases">
      Releases
    </a>
  </h3>
</div>
<br/>

Iroh is a protocol for syncing & moving bytes. Bytes of any size, on any device. At it's core, it's a peer-2-peer network built on a _magic socket_ that establishes [QUIC](https://en.wikipedia.org/wiki/QUIC) connections between peers. Peers request and provide _blobs_ of opaque bytes that are incrementally verified by their BLAKE3 hash during transfer.

## Using Iroh

Iroh is delivered as a Rust library and a CLI. Run `cargo build` to build the `iroh` CLI. To use iroh in your project, check out https://iroh.computer/install to get started.

### As a library
Disable default features when using `iroh` as a library:
`iroh = { version = "...", default-features = false }`

This removes dependencies that are only relevant when using `iroh` as a cli.

# License

Copyright 2023 N0, INC.

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
