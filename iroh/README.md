# iroh

Iroh is a library to establish direct connectivity between peers.
It's built on peer-to-peer [QUIC](https://en.wikipedia.org/wiki/QUIC) using both relays and holepunching.
The main structure for connection is the `Endpoint` entrypoint.

Peer to peer connectivity is established with the help of a _relay server_. The relay server provides Session Traversal Utilities for NAT [(STUN)](https://en.wikipedia.org/wiki/STUN) for the peers. If no direct connection can be established, the connection is relayed via the server.

Peers must know and do verify the PeerID of each other before they can connect. When using a relay server to aid the connection establishment they will register with a home relay server using their PublicKey.  Other peers which can not establish a direct connection can then establish connection via this relay server.  This will try to assist establishing a direct connection using STUN and holepunching but continue relaying if not possible.

Peers can also connect directly without using a relay server. For this, however the listening peer must be directly reachable by the connecting peer via one of it's addresses.

## Examples

Examples for `iroh` are in `iroh/examples`, run them with `cargo run --example $NAME`. Details for each example are in the file/directory itself.

## Structured Events

The library uses [tracing](https://docs.rs/tracing) to for logging as
well as for **structured events**.  Events are different from normal
logging by convention:

- The [target] has a prefix of `$crate_name::_events` and target names
  are `::` separated.

  For this library the target will always start with `iroh::_events::`.

- There is **no message**.

  Each event has a unique [target] which indicates the meaning.

- The event [fields] are exclusively used for structured data.

- The [Level] is always `DEBUG`.

This is a compromise between being able to process events using
automated tooling using custom subscribers and them still producing
distinguishing output in logs when using the default tracing
subscriber formatters.  While still being unlikely to conflict with
real modules.

[target]: https://docs.rs/tracing/latest/tracing/struct.Metadata.html#method.target
[fields]: https://docs.rs/tracing/latest/tracing/#recording-fields
[Level]: https://docs.rs/tracing/latest/tracing/struct.Level.html

### Using events

If desired an application can use the `$crate_name::_events` target to
handle events by a different subscriber.  However with the default
file logging it is already easy to search for all events, e.g. using
ripgrep:

`rg 'events::[a-z_\-:]+' path/to/iroh/logs/iroh.YYYY-MM-DD-NN.log`

Which will also highlight the full target name by default on a colour
supporting terminal.

### Development

Be cautious about adding new events.  Events aim for a high
signal-to-noise ratio.  Events should be designed to be able to
extract in an automated way.  If multiple events need to be related,
fields with special values can be used.

To make events distinct from normal logging in the code it is
recommended to write them using the `event!()` macro:

```rust
event!(
    target: "iroh::_event::subject",
    Level::DEBUG,
    field = value,
);
```

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
