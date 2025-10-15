# Relay endpoints

When an Iroh endpoint starts up, it does a latency test to see which known relay endpoint it is “closest to”. That relay server is considered the Iroh endpoint's home relay server.

An endpoint may be connected to multiple relay servers, but it will advertise its home relay endpoint as the one best used to hole-punch or relay packets through.

You do not need to know an endpoint's relay server in order to connect to them directly, if there are no firewalls or NATs between the two endpoints trying to connect. However, to have any hole punching, you must know at least one relay server to which that endpoint is connected.

We currently run 2 relay endpoints.
## North America

```rust
RelayEndpoint {
  url: format!("https://derp.iroh.network")
         .parse()
         .unwrap(),
}
```

## Europe

```rust
RelayEndpoint {
  url: format!("https://eu1.derp.iroh.network")
       .parse()
       .unwrap(),
}
```
