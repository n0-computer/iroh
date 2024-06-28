# Iroh Docker Images

## Intro

A set of docker images provided to easily run iroh in a containerized environment.
Features `iroh`, `iroh-relay` and `iroh-dns-server`.

The provided `Docker` files are intended for CI use but can be also manually built.

## Building

- All commands are run from the root folder
- If you're on macOS run `docker buildx build -f docker/Dockerfile --platform linux/arm64/v8 --tag n0computer/iroh:latest .`
- If you're on linux run `docker buildx build -f docker/Dockerfile --platform linux/amd64 --tag n0computer/iroh:latest .`

## Running

- As is: `docker run n0computer/iroh:latest`
- With parameters: `docker run -it n0computer/iroh:latest <params>`
- Provide a config file: `docker run -v /path/to/iroh.conf:/config/iroh.conf -it n0computer/iroh:latest <params> --config /config/iroh.conf`

