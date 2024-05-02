# iroh-dns-server

A server that functions as a [pkarr](https://github.com/Nuhvi/pkarr/) relay and
[DNS](https://de.wikipedia.org/wiki/Domain_Name_System) server.

This server compiles to a binary `iroh-dns-server`. It needs a config file, of
which there are two examples included:

- [`config.dev.toml`](./config.dev.toml) - suitable for local development
- [`config.prod.toml`](./config.dev.toml) - suitable for production, after
  adjusting the domain names and IP addresses

The server will expose the following services:

- A DNS server listening on UDP and TCP for DNS queries
- A HTTP and/or HTTPS server which provides the following routes:
  - `/pkarr`: `GET` and `PUT` for pkarr signed packets
  - `/dns-query`: Answer DNS queries over
    [DNS-over-HTTPS](https://datatracker.ietf.org/doc/html/rfc8484)

All received and valid pkarr signed packets will be served over DNS. The pkarr
packet origin will be appended with the origin as configured by this server.

# License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
