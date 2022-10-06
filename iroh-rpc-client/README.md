# iroh-rpc-client

[iroh](https://github.com/n0-computer/iroh) services internally communicate via
RPC, using the [gRPC protocol](https://grpc.io/) and [protocol
buffers](https://developers.google.com/protocol-buffers). This crate provides
an RPC client that can be used to talk to an [iroh
gateway](https://github.com/n0-computer/iroh/tree/main/iroh-gateway), an [iroh
p2p node](https://github.com/n0-computer/iroh/tree/main/iroh-p2p), and the
[iroh store](https://github.com/n0-computer/iroh/tree/main/iroh-store). 

The types that define the RPC protocol are maintained in
[iroh-rpc-types](https://github.com/n0-computer/iroh/tree/main/iroh-rpc-types).

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

