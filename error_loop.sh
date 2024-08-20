#!/usr/bin/env bash

echo "Building tests..."
# run once for nice output
cargo test -p iroh-gossip --no-run --release
# run again for getting the executable path
executable_path=$(cargo test -p iroh-gossip --no-run --release 2>&1 | grep "Executable" | tail -n 1 | sed -n 's/.*(\(.*\)).*/\1/p')
echo "Extracted path: ./$executable_path"

counter=0

while true; do
    counter=$((counter + 1))
    echo -n "Running tests... Attempt #$counter"

    start_time=$(date +%s%3N)
    RUST_LOG=trace "./$executable_path" gossip_net_smoke --nocapture > logs-2.txt
    err_code=$?
    end_time=$(date +%s%3N)
    duration=$((end_time - start_time))

    echo ", ${duration} ms"

    if [ $err_code -ne 0 ]; then
        echo "$(wc -l logs-2.txt) log line(s), tail:"
        tail logs-2.txt
        if grep "failed to auth" logs-2.txt; then
            mv logs-2.txt logs-last-failure.log
            echo "Error detected on attempt #$counter! Exiting loop."
            exit 1
        else
            echo "Apparently different error on attempt #$counter. Continuing."
        fi
    fi
done
