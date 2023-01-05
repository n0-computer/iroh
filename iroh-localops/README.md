# iroh localops

[![crates.io](https://img.shields.io/crates/v/iroh-localops.svg?style=flat-square)](https://crates.io/crates/iroh-localops)
[![Released API docs](https://img.shields.io/docsrs/iroh-localops?style=flat-square)](https://docs.rs/iroh-localops)
[![MIT/Apache-2.0 licensed](https://img.shields.io/crates/l/iroh-localops?style=flat-square)](../LICENSE-MIT)
[![CI](https://img.shields.io/github/workflow/status/n0-computer/iroh/Continuous%20integration?style=flat-square)](https://github.com/n0-computer/iroh/actions?query=workflow%3A%22Continuous+integration%22)

Think "devops on localhost". This crate contains iroh-specific tools for starting & stopping processes in a cross platform way. 

This crate targets three operating systems via [conditional compilation](https://doc.rust-lang.org/reference/conditional-compilation.html):
* `macos`
* `linux`
* `windows`

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
