#!/bin/bash

# Create script that runs the query example with the given arguments
cargo run --quiet --example search-v2 --features=examples -- query "$@"
