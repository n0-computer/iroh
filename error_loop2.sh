#!/usr/bin/env bash

echo "Building tests..."
# run once for nice output
cargo test --release -p iroh-net --test auth-fail || exit 1
# run again for getting the executable path
echo "Extract path..."
executable_path=$(cargo test --release -p iroh-net --test auth-fail 2>&1 | grep "Running" | tail -n 1 | sed -n 's/.*(\(.*\)).*/\1/p')
echo "Extracted path: $executable_path"

total_runs=100
failure_count=0
logdir="${LOGDIR:-logs}"

mkdir -p ./${logdir}

for ((counter=1; counter<=total_runs; counter++)); do
    echo -n "Running tests... Attempt #$counter"

    start_time=$(date +%s%3N)
    LOGFILE="$logdir/attempt-$counter.log"
    RUST_LOG=trace "$executable_path" --nocapture >& $LOGFILE
    err_code=$?
    end_time=$(date +%s%3N)
    duration=$((end_time - start_time))

    echo ", ${duration} ms"
    echo "\n\nTIME: ${duration}" >> $LOGFILE

    if [ $err_code -ne 0 ]; then
        failure_count=$((failure_count + 1))
        echo "$(wc -l $LOGFILE) log line(s), tail:"
        tail $LOGFILE
        if grep "failed to auth" $LOGFILE; then
            cp $LOGFILE logs/failure-$failure_count.log
            echo "Error detected on attempt #$counter!"
        else
            echo "Apparently different error on attempt #$counter."
        fi
    fi
done

# Calculate failure probability
failure_probability=$(echo "scale=4; $failure_count / $total_runs * 100" | bc)

echo "Test completed: $total_runs runs, $failure_count failures."
echo "Probability of failure: $failure_probability%"
