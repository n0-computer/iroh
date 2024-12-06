FROM rust:alpine AS chef

RUN update-ca-certificates
RUN apk add --no-cache musl-dev openssl-dev pkgconfig
RUN cargo install cargo-chef 
WORKDIR /iroh

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

### Builder image
FROM chef AS rust_builder

RUN update-ca-certificates
RUN apk add --no-cache musl-dev openssl-dev pkgconfig

COPY --from=planner /iroh/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

WORKDIR /iroh

# copy entire workspace
COPY . .

RUN cargo build --release --all-features

### Target image
FROM alpine:latest AS iroh-relay

RUN apk update && apk add ca-certificates && update-ca-certificates

# Copy our build, changing owndership to distroless-provided "nonroot" user,
# (65532:65532)
COPY --from=rust_builder /iroh/target/release/iroh-relay /iroh-relay

RUN chmod +x /iroh-relay

WORKDIR /

# expose the default ports
# http, https, stun, metrics
EXPOSE  80 443 3478/udp 9090
ENTRYPOINT ["/iroh-relay"]
CMD [""]

### Target image
FROM alpine:latest AS iroh-dns-server

RUN apk update && apk add ca-certificates && update-ca-certificates

# Copy our build, changing owndership to distroless-provided "nonroot" user,
# (65532:65532)
COPY --from=rust_builder /iroh/target/release/iroh-dns-server /iroh-dns-server

RUN chmod +x /iroh-dns-server

WORKDIR /

# expose the default ports
# dns, metrics
EXPOSE 53/udp 9090
ENTRYPOINT ["/iroh-dns-server"]
CMD [""]