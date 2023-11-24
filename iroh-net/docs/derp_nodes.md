# Derp Nodes

When an Iroh peer starts up, it does a latency test to see which known DERP node it is “closest to”. That derp is considered the Iroh peer’s home node.

A peer may be connected to multiple derp nodes, but it will advertise its home node as the one best used to hole-punch or relay packets through.

You do not need to know a peer's DERP node in order to connect to them directly, if there are no firewalls or NATs between the two peers trying to connect. However, to have any hole punching, you must have that peer's DERP node.

We currently have 2 DERP nodes.

## North America

```rust
DerpNode {
  url: format!("https://derp.iroh.network")
         .parse()
         .unwrap(),
  stun_only: false,
  stun_port: 3478,
}
```

## Europe

```rust
DerpNode {
  url: format!("https://eu1.derp.iroh.network")
       .parse()
       .unwrap(),
  stun_only: false,
  stun_port: 3478,
}
```
