# iroh-bytes

This crate provides blob and collection transfer support for iroh. It implements
a simple protocol based on blake3 verified streaming.

A request describes data in terms of blake3 hashes and byte ranges. It is possible to
request blobs or ranges of blobs, as well as collections.

The requester opens a quic stream to the provider and sends the request.
The provider answers with the requested data, encoded as [blake3](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) verified streams,
on the same quic stream.

This crate is usually used together with [iroh-net](https://crates.io/crates/iroh-net),
but can also be used with normal [quinn](https://crates.io/crates/quinn) connections.
Connection establishment is left up to the user or a higher level APIs such as
the iroh CLI.

## Concepts

- Blobs

A blob is a sequence of bytes of arbitrary size, without any metadata.

- Link

A link is a 32 byte blake3 hash of a blob.

- Collections

A collection is any blob that contains links in any way. The simplest collection
is just an array of 32 byte blake3 hashes.

- Provider

The side that provides data and answers request is called provider. It is waiting
for incoming requests.

- Requester

The requester is the side that requests data. It is initiating requests to one
or many providers.

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

