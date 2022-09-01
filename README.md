# iroh

Iroh is a next-generation implementation of the Interplanetary File System ([IPFS](https://ipfs.io)) for Cloud & Mobile platforms.

IPFS is a networking protocol for exchanging _content-addressed_ blocks of immutable data. “Content-addressed” means referring to data by the *hash of its content*, which makes the reference unique and verifiable. These two properties make it possible to get data from *any* node in the network that speaks the IPFS protocol, including IPFS content being served by other implementations of the protocol.

- Iroh Cloud is an IPFS implementation purpose-built for running at scale on datacenter-grade infrastructure.
- Iroh Mobile is an IPFS library for iOS & Android app development. Both libraries are operating system specific, written in Rust and wrapped in native language APIs. 

Iroh has yet to publish a release. We're targeting the end of October 2022 for an initial version.

Iroh is built & maintained by [number 0](https://n0.computer).

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br />

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
