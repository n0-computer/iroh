#!/bin/bash

# cargo run --example file_share -- share --path test_share

# cargo run  --quiet --example file-share --features=examples -- share --path "$@"

cargo run --quiet --example file-share --features=examples -- share --path "$@"