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
# rpc, nat-pmp, metrics, iroh_node_ipv4, iroh_node_ipv6
EXPOSE 4919/udp 5351 9090 11204/udp 11205/udp
ENTRYPOINT ["/iroh"]
CMD ["start"]

### Target image
FROM alpine:latest as iroh-relay

RUN apk update && apk add ca-certificates && update-ca-certificates

# Copy our build, changing owndership to distroless-provided "nonroot" user,
# (65532:65532)
COPY --from=rust_builder /iroh/target/release/iroh-relay /iroh-relay

RUN chmod +x /iroh-relay

WORKDIR /

# expose the default ports
# http, https, stun, metrics
EXPOSE  80 443 3478 9090
ENTRYPOINT ["/iroh-relay"]
CMD [""]

### Target image
FROM alpine:latest as iroh-dns-server

RUN apk update && apk add ca-certificates && update-ca-certificates

# Copy our build, changing owndership to distroless-provided "nonroot" user,
# (65532:65532)
COPY --from=rust_builder /iroh/target/release/iroh-dns-server /iroh-dns-server

RUN chmod +x /iroh-dns-server

WORKDIR /

# expose the default ports
# dns, metrics
EXPOSE 53 9090
ENTRYPOINT ["/iroh-relay"]
CMD [""]