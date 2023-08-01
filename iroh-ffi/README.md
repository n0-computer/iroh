# iroh-ffi 

> FFI bindings for Iroh

Running `cargo build --release` will produce a dynamic library and a static library.

For builds targeting older versions of MacOS, build with with:  `MACOSX_DEPLOYMENT_TARGET=10.7 && cargo build --target x86_64-apple-darwin --release`.

## Xcode and IOS 

- Run `make.sh`. 
- Make sure you have `Lib` folder ("New Group") in your Xcode project.
- After that you can drag the `IrohLib` folder into the `Lib` folder in Xcode. 
- Then you add it to the `Frameworks, Libraries, and Embedded Content` in the `General` settings of your project. 
- Now you can just import the library in Swift with a standard import statement like `import IrohLib`.

## Development


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
