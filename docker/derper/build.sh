#!/bin/sh
cargo build -p iroh-net --bin derper --features derper --target x86_64-unknown-linux-musl --release
rm -rf target/docker
mkdir -p target/docker
mv target/x86_64-unknown-linux-musl/release/derper target/docker
docker build target/docker -f docker/derper/Dockerfile -t n0-computer/derper