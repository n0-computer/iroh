# DERP nodes, or DERPers

When an Iroh node starts up, it does a latency test to see which known DERP node it is “closest to”. That DERPer (as we sometimes call a DERP node) is considered the Iroh node's home DERPer.

A node may be connected to multiple DERPers, but it will advertise its home DERP node as the one best used to hole-punch or relay packets through.

You do not need to know a node's DERPer in order to connect to them directly, if there are no firewalls or NATs between the two nodes trying to connect. However, to have any hole punching, you must know at least one DERPer to which that node is connected.

We currently run 2 DERP nodes.
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
