use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct DerpMap {
    pub regions: Vec<DerpRegion>,
}

#[derive(Debug, Clone)]
pub struct DerpRegion {
    pub nodes: Vec<DerpNode>,
    pub avoid: bool,
    pub region_id: usize,
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
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}
