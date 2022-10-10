# Iroh Metrics

The metrics collection interface for
[iroh](https://github.com/n0-computer/iroh) services.

## ENV Variables

- `IROH_METRICS_DEBUG` - redirects traces to stdout if the flag is set to `true` (default: ``)
- `IROH_METRICS_COLLECTOR_ENDPOINT` - endpoint where traces will be routed (default: `http://localhost:4317`)
- `IROH_METRICS_PROM_GATEWAY_ENDPOINT` - endpoint where prometheus metrics will be pushed (default: `http://localhost:9091`)
