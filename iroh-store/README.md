# iroh store

[![crates.io](https://img.shields.io/crates/v/iroh-store.svg?style=flat-square)](https://crates.io/crates/iroh-store)
[![Released API docs](https://img.shields.io/docsrs/iroh-store?style=flat-square)](https://docs.rs/iroh-store)
[![MIT/Apache-2.0 licensed](https://img.shields.io/crates/l/iroh-store?style=flat-square)](../LICENSE-MIT)
[![CI](https://img.shields.io/github/workflow/status/n0-computer/iroh/Continuous%20integration?style=flat-square)](https://github.com/n0-computer/iroh/actions?query=workflow%3A%22Continuous+integration%22)

Storage for [iroh](https://github.com/n0-computer/iroh). This provides an gRPC
API for storing IPFS data in a [RocksDB database](http://rocksdb.org/).

## How to run

```sh
# From the root of the workspace
> cargo run --release -p iroh-store
```

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

