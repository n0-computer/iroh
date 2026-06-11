# Developing iroh

## Structured events

The library uses [tracing] both for logging and for *structured events*.
Events differ from normal logging by convention:

- The [target] is prefixed with `iroh::_events::`, with `::`-separated names.
- There is **no message**; the unique target indicates the meaning.
- The [fields] carry exclusively structured data.
- The [Level] is always `DEBUG`.

This lets automated tooling process events through custom subscribers while
still producing distinct output under the default tracing formatters, and makes
them unlikely to conflict with real modules.

An application can subscribe to the `iroh::_events` target separately. With the
default file logging it is also easy to grep for all events:

```sh
rg 'events::[a-z_\-:]+' path/to/iroh/logs/iroh.YYYY-MM-DD-NN.log
```

When adding events, aim for a high signal-to-noise ratio and design them to be
extracted automatically. To keep them distinct from normal logging, write them
with the `event!()` macro:

```rust,ignore
event!(
    target: "iroh::_events::subject",
    Level::DEBUG,
    field = value,
);
```

## Building documentation

Building the documentation is only supported with `--all-features`. To also
document the cargo features required for certain APIs, pass the `iroh_docsrs`
cfg to rustdoc, which requires nightly Rust:

```sh
RUSTDOCFLAGS="--cfg iroh_docsrs" cargo +nightly doc --workspace --no-deps --all-features
```

[target]: https://docs.rs/tracing/latest/tracing/struct.Metadata.html#method.target
[fields]: https://docs.rs/tracing/latest/tracing/#recording-fields
[Level]: https://docs.rs/tracing/latest/tracing/struct.Level.html
[tracing]: https://docs.rs/tracing
