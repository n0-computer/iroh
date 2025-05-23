#!/bin/bash

# cargo run --example file-download -- download --node-id <node_id> --output-path <path>

cargo run --quiet --example file-download --features=examples -- download  --output-path "$1" --node-id "$2"