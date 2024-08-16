#!/usr/bin/env bash

echo "Building tests..."
cargo test -p iroh-gossip --no-run --release

counter=0

while true; do
    counter=$((counter + 1))
    echo "Running tests... Attempt #$counter"
    RUST_LOG=trace ./target/release/deps/iroh_gossip-820fc8bcba99d1cc gossip_net_smoke > logs-2.txt
    if [ $? -ne 0 ]; then
        echo "Error detected on attempt #$counter! Exiting loop."
        exit 1
    fi
done
