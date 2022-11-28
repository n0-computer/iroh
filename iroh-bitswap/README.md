# iroh bitswap

[![crates.io](https://img.shields.io/crates/v/iroh-bitswap.svg?style=flat-square)](https://crates.io/crates/iroh-bitswap)
[![Released API docs](https://img.shields.io/docsrs/iroh-bitswap?style=flat-square)](https://docs.rs/iroh-bitswap)
[![MIT/Apache-2.0 licensed](https://img.shields.io/crates/l/iroh-bitswap?style=flat-square)](../LICENSE-MIT)
[![CI](https://img.shields.io/github/workflow/status/n0-computer/iroh/Continuous%20integration?style=flat-square)](https://github.com/n0-computer/iroh/actions?query=workflow%3A%22Continuous+integration%22)

This contains an implementation of the [IPFS bitswap
protocol](https://docs.ipfs.tech/concepts/bitswap/). It sends blocks of data to
other peers in the IPFS network who want them, and receives blocks requested by
the client from the network.

It is part of [iroh](https://github.com/n0-computer/iroh).

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
