### Backend Builder
FROM rust:latest AS rust_builder

RUN update-ca-certificates

# has the side effect of updating the crates.io index & installing rust toolchain
# called in a separate step for nicer caching. the command itself will fail,
# b/c empty-library is not a dependency, so we override with an exit code 0
RUN cargo install empty-library; exit 0

WORKDIR /iroh

# copy entire workspace
COPY . .

RUN cargo clean
RUN cargo build --bin iroh --release --all-features

### Final Image
FROM ubuntu:latest as iroh

RUN apt-get update
RUN apt-get install ca-certificates -y
RUN update-ca-certificates

# Copy our build, changing owndership to distroless-provided "nonroot" user,
# (65532:65532)
COPY --from=rust_builder /iroh/target/release/iroh /iroh

RUN chmod +x /iroh

WORKDIR /

# Use nonroot (unprivileged) user
# USER nonroot
# expose the default ports
EXPOSE 4433 8000 9090 4919
ENTRYPOINT ["/iroh --rpc-addr 0.0.0.0:4919 start"]
