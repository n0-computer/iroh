# iroh-sync

Multi-dimensional key-value documents with an efficient synchronization protocol.

The crate operates on *Replicas*. A replica contains an unlimited number of
*Entrys*. Each entry is identified by a key, its author, and the replica's
namespace. Its value is the 32-byte BLAKE3 hash of the entry's content data,
the size of this content data, and a timestamp.
The content data itself is not stored or transferred through a replica.

All entries in a replica are signed with two keypairs:

* The *Namespace* key, as a token of write capability. The public key is the *NamespaceId*, which
  also serves as the unique identifier for a replica.
* The *Author* key, as a proof of authorship. Any number of authors may be created, and
  their semantic meaning is application-specific. The public key of an author is the [AuthorId].

Replicas can be synchronized between peers by exchanging messages. The synchronization algorithm
is based on a technique called *range-based set reconciliation*, based on [this paper][paper] by
Aljoscha Meyer:

> Range-based set reconciliation is a simple approach to efficiently compute the union of two
sets over a network, based on recursively partitioning the sets and comparing fingerprints of
the partitions to probabilistically detect whether a partition requires further work.

The crate exposes a generic storage interface with in-memory and persistent, file-based
implementations. The latter makes use of [`redb`], an embedded key-value store, and persists
the whole store with all replicas to a single file.

[paper]: https://arxiv.org/abs/2212.13567


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
