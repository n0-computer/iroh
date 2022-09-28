# Iroh One

Single binary of iroh services (gateway, p2p, store) communicating via mem channels.

## Running / Building

`cargo run --release -- -p 10000 --store-path=tmpstore`

### Options

- Run with `cargo run --release -- -h` for details
- `-wcf` Writeable, Cache, Fetch (options to toggle write enable, caching mechanics and fetching from the network); currently exists but is not implemented
- `-p` Port the gateway should listen on
- `--store-path` Path for the iroh-store

### Features

- `uds-gateway` - enables the usage and binding of the http gateway over UDS.

### Reference

- [Gateway](../iroh-gateway/README.md)
- [P2P](../iroh-p2p/README.md)
- [Store](../iroh-store/README.md)