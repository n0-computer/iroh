# iroh-resolver

Resolver for [iroh](https://github.com/n0-computer/iroh). It retrieves data
associated with an IPFS CID from the [iroh
store](https://github.com/n0-computer/iroh/tree/main/iroh-store), or if not
available, uses [iroh
p2p](https://github.com/n0-computer/iroh/tree/main/iroh-p2p) to retrieve it
from the IPFS network. 

This crate also provides a way to take a directory of files, or a single file,
and chunk it into smaller parts that can be stored, and assemble them back
together again.

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

