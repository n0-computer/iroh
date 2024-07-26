<h1 align="center"><a href="https://iroh.computer"><img alt="iroh" src="./.img/iroh_wordmark.svg" width="100" /></a></h1>

<h3 align="center">
A toolkit for building distributed applications
</h3>

[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square)](https://docs.rs/iroh/)
[![Crates.io](https://img.shields.io/crates/v/iroh.svg?style=flat-square)](https://crates.io/crates/iroh)
[![downloads](https://img.shields.io/crates/d/iroh.svg?style=flat-square)](https://crates.io/crates/iroh)
[![Chat](https://img.shields.io/discord/1161119546170687619?logo=discord&style=flat-square)](https://discord.com/invite/DpmJgtU7cW)
[![Youtube](https://img.shields.io/badge/YouTube-red?logo=youtube&logoColor=white&style=flat-square)](https://www.youtube.com/@n0computer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE)
[![CI](https://github.com/n0-computer/iroh/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/n0-computer/iroh/actions/workflows/ci.yml)

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

## Features

- Documents - Authors create and join documents: mutable key-value stores that multiple users read from, write to, and sync with, subscribing to live updates in real time.
- Blobs - Iroh works with content-addressed blobs of opaque data, which are often the bytes of a file.
- Networking - At the core of iroh is the ability to connect any two devices, no matter where they are.

## Overview

Iroh is a protocol for syncing & moving bytes. Bytes of any size, on any device. At its core, it's a peer-2-peer network built on a _magic socket_ that establishes [QUIC](https://en.wikipedia.org/wiki/QUIC) connections between peers. Peers request and provide _blobs_ of opaque bytes that are incrementally verified by their BLAKE3 hash during transfer.

## Getting Started

Iroh is delivered as a Rust library and a CLI.

### Library

Run `cargo add iroh`, to add `iroh` to your project.

### CLI

Check out https://iroh.computer/docs/install to get started.

The implementation lives in the `iroh-cli` crate.

### Links

- [Introducing Iroh (video)](https://www.youtube.com/watch?v=RwAt36Xe3UI_)
- [Iroh Examples](https://github.com/n0-computer/iroh-examples)


## License

Copyright 2024 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
