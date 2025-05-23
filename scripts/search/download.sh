#!/bin/bash

# cargo run --example file-download -- download --node-id <node_id> --output-path <path>

cargo run --quiet --example file-download --features=examples -- download  --relay-url "https://use1-1.relay.iroh.network./" --output-path "$1" --node-id "$2"