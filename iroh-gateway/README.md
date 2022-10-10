# Iroh Gateway

A Rust implementation of an [IPFS
gateway](https://docs.ipfs.tech/concepts/ipfs-gateway/) based on
[iroh](https://github.com/n0-computer/iroh). An IPFS gateway allows you to
access content on the IPFS network over HTTP.

## Running / Building

`cargo run -- -p 10000`

### Options

- Run with `cargo run -- -h` for details
- `-wcf` Writeable, Cache, Fetch (options to toggle write enable, caching mechanics and fetching from the network); currently exists but is not implemented
- `-p` Port the gateway should listen on

## ENV Variables

- `IROH_INSTANCE_ID` - unique instance identifier, preferably some name than hard id (default: generated lower & snake case name)
- `IROH_ENV` - indicates the service environment (default: `dev`)

## Endpoints

| Endpoint                          | Flag                                       | Description                                                                             | Default     |
|-----------------------------------|--------------------------------------------|-----------------------------------------------------------------------------------------|-------------|
| `/ipfs/:cid` & `/ipfs/:cid/:path` | `?format={"", "fs", "raw", "car"}`         | Specifies the serving format & content-type                                             | `""/fs`     |
|                                   | `?filename=DESIRED_FILE_NAME`              | Specifies a filename for the attachment                                                 | `{cid}.bin` |
|                                   | `?download={true, false}`                  | Sets content-disposition to attachment, browser prompts to save file instead of loading | `false`     |
|                                   | `?force_dir={true, false}`                 | Lists unixFS directories even if they contain an `index.html` file                      | `false`     |
|                                   | `?uri=ENCODED_URL`                         | Query parameter to handle navigator.registerProtocolHandler Web API ie. ipfs://         | `""`        |
