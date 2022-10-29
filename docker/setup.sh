#!/bin/sh

usage() {
    cat 1>&2 <<EOF
iroh quickstart

USAGE:
    ./iroh.sh [COMMANDS] [FLAGS] [OPTIONS]

COMMANDS:
    init          Initialize iroh
    start         Start iroh services
    stop          Stop iroh services
    quickstart    Init iroh and start services

FLAGS:
    -h, --help              Prints help information
EOF
}

fetch_service() {
    service=$1
    target=$2
    uri="https://vorc.iroh.computer/bin/${service}/${target}"
    echo "Fetching ${uri}"
    wget --tries=3 --quiet "$uri" -O ~/.iroh/bin/$service
    chmod +x ~/.iroh/bin/$service
}

init () {
    if [ "$OS" = "Windows_NT" ]; then
        echo "Error: this installer only works on linux & macOS." 1>&2
        exit 1
    else
        case $(uname -sm) in
        "Darwin x86_64") target="darwin/x86_64/latest" ;;
        "Darwin arm64") target="darwin/aarch64/latest" ;;
        "Linux x86_64") target="linux/amd64/latest" ;;
        "Linux arm64"|"Linux aarch64") target="linux/aarch64/latest" ;;
        *) target="linux/amd64/latest" ;;
        esac
    fi

    mkdir -p ~/.iroh/bin
    mkdir -p ~/.iroh/log

    fetch_service "iroh-gateway" "${target}"
    fetch_service "iroh-p2p" "${target}"
    fetch_service "iroh-store" "${target}"
    fetch_service "iroh" "${target}"
}

run_service() {
    service=$1
    params=$2
    PID=$(pgrep $service)
    if [ -n "$PID" ]; then
            echo "$service already running"
    else
            echo "starting $service..."
            nohup ~/.iroh/bin/$service $params > ~/.iroh/log/$service.log 2>&1 &
            sleep 1
            PID=$(pgrep $service)
            if [ -n "$PID" ]; then
                    echo "$service started"
            else
                    echo "failed to start $service"
                    stop
                    exit 1
            fi
            echo "view logs at ~/.iroh/log/$service.log"
    fi
}

stop_service() {
    service=$1
    PID=$(pgrep $service)
    if [ -n "$PID" ]; then
            echo "stopping $service..."
            kill -9 $PID
    else
            echo "$service already stopped"
    fi
}

start() {
    store_params="--path "$HOME"/.iroh/store"
    run_service "iroh-store" "$store_params"
    run_service "iroh-p2p"
    run_service "iroh-gateway" "--tracing"
    echo "\niroh started"
    echo "iroh-gateway available at http://localhost:9050"
    echo "you can run iroh (CLI) from ~/.iroh/bin/iroh"
}

stop() {
    stop_service "iroh-gateway"
    stop_service "iroh-p2p"
    stop_service "iroh-store"
}

quickstart() {
    init
    start
}

main() {
    local need_tty=yes
    local service=""
    local cmd=""
    for arg in "$@"; do
        case "$arg" in
            -h|--help)
                usage
                shift
                exit 0
                ;;
            -y)
                # user wants to skip the prompt -- we don't need /dev/tty
                need_tty=no
                shift
                ;;
            init)
                cmd="init"
                shift
                ;;
            start)
                cmd="start"
                shift
                ;;
            run)
                cmd="run"
                shift
                ;;
            stop)
                cmd="stop"
                shift
                ;;
            quickstart)
                cmd="quickstart"
                shift
                ;;
            *)
                ;;
        esac
    done

    if [ "$cmd" = "init" ]; then
        init
        exit 0
    fi
    if [ "$cmd" = "start" ]; then
        start
        exit 0
    fi
    if [ "$cmd" = "run" ]; then
        if [ "$cmd" = "run" ]; then
            run_service "$1" "$2"
            exit 0
        fi
        echo "run needs a service name:   iroh-gateway, iroh-p2p, iroh-store"
        exit 1
    fi
    if [ "$cmd" = "stop" ]; then
        stop
        exit 0
    fi
    if [ "$cmd" = "quickstart" ]; then
        quickstart
        exit 0
    fi
    if [ "$cmd" = "" ]; then
        usage
        exit 1
    fi
}

main "$@" || exit 1