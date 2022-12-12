# iroh-rpc-client

[iroh](https://github.com/n0-computer/iroh) services internally communicate via
RPC, using the [quic-rpc](https://github.com/n0-computer/quic-rpc) RPC system.

TLDR: currently bincode encoded messages sent as http2 frames.

These channels are meant for internal communication and are not a stable API.

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

