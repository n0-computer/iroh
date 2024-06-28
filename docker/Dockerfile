### Builder image
FROM rust:alpine AS rust_builder

RUN update-ca-certificates
RUN apk add --no-cache musl-dev openssl-dev pkgconfig

# has the side effect of updating the crates.io index & installing rust toolchain
# called in a separate step for nicer caching. the command itself will fail,
# b/c empty-library is not a dependency, so we override with an exit code 0
RUN cargo install empty-library; exit 0

WORKDIR /iroh

# copy entire workspace
COPY . .

RUN cargo clean
RUN cargo build --release --all-features

### Target image
FROM alpine:latest as iroh

RUN apk update && apk add ca-certificates && update-ca-certificates

# Copy our build, changing owndership to distroless-provided "nonroot" user,
# (65532:65532)
COPY --from=rust_builder /iroh/target/release/iroh /iroh

RUN chmod +x /iroh

WORKDIR /

# expose the default ports
EXPOSE 4433 4919 9090
ENTRYPOINT ["/iroh"]
CMD ["start"]