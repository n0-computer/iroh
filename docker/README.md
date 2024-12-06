# Iroh Docker Images

## Intro

A set of docker images provided to easily run iroh in a containerized environment.
Features `iroh-relay` and `iroh-dns-server`.

The provided `Docker` files are intended for CI use but can be also manually built.

## Building

- All commands are run from the root folder
- If you're on macOS run `docker buildx build -f docker/Dockerfile --target iroh-relay --platform linux/arm64/v8 --tag n0computer/iroh-relay:latest .`
- If you're on linux run `docker buildx build -f docker/Dockerfile --target iroh-relay --platform linux/amd64 --tag n0computer/iroh-relay:latest .`
- Switch out `--target iroh-relay` for `iroh-dns-server`

## Running

### iroh-relay

- Provide a config file: `docker run -v /path/to/iroh-relay.conf:/config/iroh-relay.conf -p 80:80 -p 443:443 -p 3478:3478/udp -p 9090:9090 -it n0computer/iroh-relay:latest <params> --config /config/iroh-relay.conf`

### iroh-dns-server

- Provide a config file: `docker run -v /path/to/iroh-dns-server.conf:/config/iroh-dns-server.conf -p 53:53/udp -p 9090:9090 -it n0computer/iroh-dns-server:latest <params> --config /config/iroh-dns-server.conf`