# iroh

The iroh crate defines both the `iroh` library and `iroh` command-line interface (CLI).

For more details on Iroh, see https://iroh.computer.

## Building the CLI

Simply run `cargo build` from the project root, it produces the `iroh` CLI by default.

## Using as a rust crate

Because iroh builds the CLI by default, you should disable `default-features` when importing the `iroh` crate via cargo:

```toml
[dependencies]
iroh = { version = "...", default-features = false }
```

## Running Examples

Examples are located in `iroh/examples`. Run them with `cargo run --example`. eg: `cargo run --example hello-world`. At the top of each example file is a comment describing how to run the example.

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
