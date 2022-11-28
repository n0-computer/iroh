# iroh-car

[![crates.io](https://img.shields.io/crates/v/iroh-car.svg?style=flat-square)](https://crates.io/crates/iroh-car)
[![Released API docs](https://img.shields.io/docsrs/iroh-car?style=flat-square)](https://docs.rs/iroh-car)
[![MIT/Apache-2.0 licensed](https://img.shields.io/crates/l/iroh-car?style=flat-square)](../LICENSE-MIT)
[![CI](https://img.shields.io/github/workflow/status/n0-computer/iroh/Continuous%20integration?style=flat-square)](https://github.com/n0-computer/iroh/actions?query=workflow%3A%22Continuous+integration%22)

[CAR file](https://ipld.io/specs/transport/car/) support for iroh. "CAR" stands
for Content Addressable aRchives. A CAR file typically contains a serialized
representation of an [IPLD
DAG](https://docs.ipfs.tech/concepts/merkle-dag/#merkle-directed-acyclic-graphs-dags),
though is general enough to contain arbitrary IPLD blocks.

Currently supports only [v1](https://ipld.io/specs/transport/car/carv1/).

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

