pub mod derp;
pub mod interfaces;
pub mod magicsock;
pub mod monitor;
pub mod netcheck;
pub mod ping;
pub mod portmapper;
pub mod stun;

mod cfg;
mod clock;
mod disco;
mod hostinfo;
pub mod key;
mod netmap;

use std::net::{IpAddr, Ipv6Addr};

// TODO: replace with IpAddr::to_canoncial once stabilized.
pub fn to_canonical(ip: IpAddr) -> IpAddr {
    match ip {
        ip @ IpAddr::V4(_) => ip,
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                IpAddr::V4(ip)
            } else {
                IpAddr::V6(ip)
            }
        }
    }
}
// Copied from std lib, not stable yet
pub const fn is_unicast_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}
