# iroh one

[![crates.io](https://img.shields.io/crates/v/iroh-one.svg?style=flat-square)](https://crates.io/crates/iroh-one)
[![Released API docs](https://img.shields.io/docsrs/iroh-one?style=flat-square)](https://docs.rs/iroh-one)
[![MIT/Apache-2.0 licensed](https://img.shields.io/crates/l/iroh-one?style=flat-square)](../LICENSE-MIT)
[![CI](https://img.shields.io/github/workflow/status/n0-computer/iroh/Continuous%20integration?style=flat-square)](https://github.com/n0-computer/iroh/actions?query=workflow%3A%22Continuous+integration%22)

Single binary of [iroh](https://github.com/n0-computer/iroh) services
([gateway](https://github.com/n0-computer/iroh/tree/main/iroh-gateway),
[p2p](https://github.com/n0-computer/iroh/tree/main/iroh-p2p),
[store](https://github.com/n0-computer/iroh/tree/main/iroh-store))
communicating via mem channels. This is an alternative to deploying the iroh
services as micro services.

## Running / Building

`cargo run --release -- -p 10000 --store-path=tmpstore`

### Options

- Run with `cargo run --release -- -h` for details
- `-wcf` Writeable, Cache, Fetch (options to toggle write enable, caching mechanics and fetching from the network); currently exists but is not implemented
- `-p` Port the gateway should listen on
- `--store-path` Path for the iroh-store

### Features

- `http-uds-gateway` - enables the usage and binding of the http gateway over UDS. This is independent from the rpc control endpoint which uses the same default and configuration as `iroh-gateway`.

### Reference

- [Gateway](../iroh-gateway/README.md)
- [P2P](../iroh-p2p/README.md)
- [Store](../iroh-store/README.md)

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br/>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>

 
