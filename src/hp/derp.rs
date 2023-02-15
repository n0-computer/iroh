use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub mod http {
    use std::net::SocketAddr;

    use anyhow::Result;

    #[derive(Default, Debug, Clone, PartialEq, Eq)]
    pub struct Client {}

    impl Client {
        pub fn local_addr(&self) -> Option<SocketAddr> {
            todo!()
        }
        pub async fn ping(&self) -> Result<()> {
            todo!()
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct DerpMap {
    pub regions: HashMap<usize, DerpRegion>,
}

impl DerpMap {
    /// Returns the sorted region IDs.
    pub fn region_ids(&self) -> Vec<usize> {
        let mut ids: Vec<_> = self.regions.keys().copied().collect();
        ids.sort();
        ids
    }
}

/// A geographic region running DERP relay node(s).
#[derive(Debug, Clone)]
pub struct DerpRegion {
    /// A unique integer for a geographic region.
    pub region_id: usize,
    pub nodes: Vec<DerpNode>,
    pub avoid: bool,
    pub region_code: usize,
}

#[derive(Debug, Clone)]
pub struct DerpNode {
    pub name: String,
    pub region_id: usize,
    pub host_name: String,
    pub stun_only: bool,
    pub stun_port: u16,
    pub stun_test_ip: Option<IpAddr>,
    // Optionally forces an IPv4 address to use, instead of using DNS.
    // If `None`, A record(s) from DNS lookups of HostName are used.
    // If `Disabled`, IPv4 is not used;
    pub ipv4: UseIpv4,
    // Optionally forces an IPv6 address to use, instead of using DNS.
    // If `None`, A record(s) from DNS lookups of HostName are used.
    // If `Disabled`, IPv4 is not used;
    pub ipv6: UseIpv6,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UseIpv4 {
    None,
    Disabled,
    Some(Ipv4Addr),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UseIpv6 {
    None,
    Disabled,
    Some(Ipv6Addr),
}
