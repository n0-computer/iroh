# iroh-rpc-types

This crate defines types for use by the
[iroh-rpc-client](https://github.com/n0-computer/iroh/tree/main/iroh-rpc-client),
which is used for [iroh](https://github.com/n0-computer/iroh) services to
communicate internally via RPC. The protocol used is [gRPC](https://grpc.io/).
This crate defines the gRPC types in the form of [Protocol
Buffers](https://developers.google.com/protocol-buffers). It uses the [Tonic
framework](https://github.com/hyperium/tonic) to expose the gRPC types to Rust.

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
