# C bindings for Iroh

Running `cargo build --release` will produce a dynamic libaray. `libiroh.h` is a handcrafted header file for that library. Should work on all platforms, I've only tested it on MacOS so far.

For builds targeting older versions of MacOS, build with with:  `MACOSX_DEPLOYMENT_TARGET=10.7 && cargo build --target x86_64-apple-darwin --release`.

## Why not use [cbindgen](https://github.com/eqrion/cbindgen)?
I (b5) have tried, not much success so far. If someone else wants to give it a go, be my guest.