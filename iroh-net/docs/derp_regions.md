# Derp Regions

A DERP region is a collection of DERP nodes in a relatively similar geographical area. All the DERP nodes in a single DERP region are connected to every other node in that region through a mesh network. They can all act as packet forwarders for each other. When an Iroh peer starts up, it does a latency test to see which region it is “closest to”. That region is considered the Iroh peer’s home region.

A peer may be connected to multiple regions, but it will advertise its home region as the one best used to hole-punch or relay packets through.

When attempting to connect to another peer, it is not required to pass in that peer’s DERP region, but if the other peer is behind a NAT, the only way to attempt to hole punch directly through to it is by passing down a DERP region. It is also possible that the DERP region that the remote Iroh peer is connected to is one that you have no dialing information about. However, that is unlikely to happen if you use the default regions and nodes we have specified here. These also exist as defaults in the code.

We currently have 2 derp regions, with a single node in each.

Region ID `65535` is reserved for testing and experiments.

## North America

```rust

    DerpRegion {
        region_id: 1,
        nodes: vec![
                DerpNode {
                    name: "default-1".into(),
                    region_id: 1,
                    url: format!("https://derp.iroh.network")
                        .parse()
                        .unwrap(),
                    stun_only: false,
                    stun_port: 3478,
                    ipv4: UseIpv4::Some(std::net::Ipv4Addr::new(35, 175, 99, 113)),
                    ipv6: UseIpv6::TryDns,
                    stun_test_ip: None,
                }
			],
        avoid: false,
        region_code: "default-1".into(),
    }
```

## Europe

```rust

    DerpRegion {
        region_id: 2,
        nodes: vec![
                DerpNode {
                    name: "default-1".into(),
                    region_id: 2,
                    url: format!("https://eu1.derp.iroh.network")
                        .parse()
                        .unwrap(),
                    stun_only: false,
                    stun_port: 3478,
                    ipv4: UseIpv4::Some(std::net::Ipv4Addr::new(52, 30, 229, 248)),
                    ipv6: UseIpv6::TryDns,
                    stun_test_ip: None,
                }
			],
        avoid: false,
        region_code: "default-2".into(),
    }
```
