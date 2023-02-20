<h1 align="center">iroh</h1>
<div align="center">
 <strong>
   Send data over the internet.
 </strong>
</div>

<br />

<div align="center">
  <!-- Crates version -->
  <a href="https://crates.io/crates/iroh">
    <img src="https://img.shields.io/crates/v/iroh.svg?style=flat-square"
    alt="Crates.io version" />
  </a>
  <!-- Downloads -->
  <a href="https://crates.io/crates/iroh">
    <img src="https://img.shields.io/crates/d/iroh.svg?style=flat-square"
      alt="Download" />
  </a>
  <!-- docs.rs docs -->
  <a href="https://docs.rs/iroh">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square"
      alt="docs.rs docs" />
  </a>
</div>

<div align="center">
  <h3>
    <a href="https://docs.rs/iroh">
      API Docs
    </a>
    <span> | </span>
    <a href="https://github.com/n0-computer/iroh/releases">
      Releases
    </a>
  </h3>
</div>
<br/>

## Usage

### Cli
Sending data
```sh
$ ./iroh provide <file>
```

Receiving data
```sh
$ ./iroh get <hash>
```

### As a library
Disable default features when using `iroh` as a library:
`iroh = { version: "...", default-features = false }`

This removes dependencies that are only relevant when using `iroh` as
a library.

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
