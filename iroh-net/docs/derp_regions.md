# Derp Regions

We currently have 2 derp regions, with a single node in each.

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
