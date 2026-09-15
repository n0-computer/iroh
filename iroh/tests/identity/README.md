# Identity integration tests

`tests/identity.rs` collects the ordinary native identity tests into one Cargo
test target. Run them from the repository root:

```sh
cargo test -p iroh --features unstable-identity --locked --test identity
```

## Released-version interoperability

`released-peer/` is a separate workspace pinned to crates.io iroh, iroh-base,
and iroh-relay 1.1.0 and rustls 0.23.41. It must remain independent of the main
workspace so the test uses released dependencies instead of the current checkout.
The test exchanges authenticated application data in both dialing directions.
It is ignored by default because the peer binary must be built first.

```sh
cargo build --manifest-path iroh/tests/identity/released-peer/Cargo.toml --locked \
  --target-dir iroh/tests/identity/released-peer/target
IROH_RELEASED_IDENTITY_PEER="$PWD/iroh/tests/identity/released-peer/target/debug/iroh-released-identity-peer" \
  cargo test -p iroh --features unstable-identity --locked --test identity released:: -- --ignored
```

## NAT traversal

`nat.rs` is the separate `identity_nat` Cargo target because it needs Linux
network namespaces. It places two ML-DSA-65 peers behind port-restricted NATs,
connects using a relay contact, validates a direct path, and exchanges data.
Run with unprivileged user namespaces enabled and `nft` and `tc` on `PATH`:

```sh
unshare -Urnm cargo test -p iroh --features unstable-identity --locked --test identity_nat
```

On Linux systems without clang/lld, prefix Cargo commands with
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc RUSTFLAGS=''`.
