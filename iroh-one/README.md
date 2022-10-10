# Iroh One

Single binary of [iroh](https://github.com/n0-computer/iroh) services
([gateway](https://github.com/n0-computer/iroh/tree/main/iroh-gateway),
[p2p](https://github.com/n0-computer/iroh/tree/main/iroh-p2p),
[store](https://github.com/n0-computer/iroh/tree/main/iroh-store))
communicating via mem channels. This is an alternative to deploying the iroh
services as micro services.

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
