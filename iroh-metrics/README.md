# iroh metrics

[![crates.io](https://img.shields.io/crates/v/iroh-metrics.svg?style=flat-square)](https://crates.io/crates/iroh-metrics)
[![Released API docs](https://img.shields.io/docsrs/iroh-metrics?style=flat-square)](https://docs.rs/iroh-metrics)
[![MIT/Apache-2.0 licensed](https://img.shields.io/crates/l/iroh-metrics?style=flat-square)](../LICENSE-MIT)
[![CI](https://img.shields.io/github/workflow/status/n0-computer/iroh/Continuous%20integration?style=flat-square)](https://github.com/n0-computer/iroh/actions?query=workflow%3A%22Continuous+integration%22)


The metrics collection interface for [iroh](https://github.com/n0-computer/iroh) services.

## ENV Variables

- `IROH_METRICS_DEBUG` - redirects traces to stdout if the flag is set to `true` (default: ``)
- `IROH_METRICS_COLLECTOR_ENDPOINT` - endpoint where traces will be routed (default: `http://localhost:4317`)
- `IROH_METRICS_PROM_GATEWAY_ENDPOINT` - endpoint where prometheus metrics will be pushed (default: `http://localhost:9091`)

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br/>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
