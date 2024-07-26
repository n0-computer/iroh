# iroh-gossip

This crate implements the `iroh-gossip` protocol.
It is based on *epidemic broadcast trees* to disseminate messages among a swarm of peers interested in a *topic*. 
The implementation is based on the papers [HyParView](https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf) and [PlumTree](https://asc.di.fct.unl.pt/~jleitao/pdf/srds07-leitao.pdf).

The crate is made up from two modules:
The `proto` module is the protocol implementation, as a state machine without any IO.
The `net` module connects the protocol to the networking stack from `iroh-net`.

The `net` module is optional behind the `net` feature flag (enabled by default).


# License

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
