# Relay nodes

When an Iroh node starts up, it does a latency test to see which known relay node it is “closest to”. That relay server is considered the Iroh node's home relay server.

A node may be connected to multiple relay servers, but it will advertise its home relay node as the one best used to hole-punch or relay packets through.

You do not need to know a node's relay server in order to connect to them directly, if there are no firewalls or NATs between the two nodes trying to connect. However, to have any hole punching, you must know at least one relay server to which that node is connected.

We currently run 2 relay nodes.
## North America

```rust
RelayNode {
  url: format!("https://derp.iroh.network")
         .parse()
         .unwrap(),
  stun_only: false,
  stun_port: 3478,
}
```

## Europe

```rust
RelayNode {
  url: format!("https://eu1.derp.iroh.network")
       .parse()
       .unwrap(),
  stun_only: false,
  stun_port: 3478,
}
```
