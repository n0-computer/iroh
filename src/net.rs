//! Networking related utilities

use std::net::{IpAddr, Ipv6Addr};

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;

/// List of machine's IP addresses.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalAddresses {
    /// Loopback addresses.
    pub loopback: Vec<IpAddr>,
    /// Regular addresses.
    pub regular: Vec<IpAddr>,
}

impl Default for LocalAddresses {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalAddresses {
    /// Returns the machine's IP addresses.
    /// If there are no regular addresses it will return any IPv4 linklocal or IPv6 unique local
    /// addresses because we know of environments where these are used with NAT to provide connectivity.
    pub fn new() -> Self {
        let ifaces = get_interfaces();

        let mut loopback = Vec::new();
        let mut regular4 = Vec::new();
        let mut regular6 = Vec::new();
        let mut linklocal4 = Vec::new();
        let mut ula6 = Vec::new();

        for iface in ifaces {
            if !iface.is_up {
                // Skip down interfaces
                continue;
            }
            let ifc_is_loopback = iface.is_loopback;

            for ip in iface.addrs {
                let ip = to_canonical(ip);

                if ip.is_loopback() || ifc_is_loopback {
                    loopback.push(ip);
                } else if is_link_local(ip) {
                    if ip.is_ipv4() {
                        linklocal4.push(ip);
                    }

                    // We know of no cases where the IPv6 fe80:: addresses
                    // are used to provide WAN connectivity. It is also very
                    // common for users to have no IPv6 WAN connectivity,
                    // but their OS supports IPv6 so they have an fe80::
                    // address. We don't want to report all of those
                    // IPv6 LL to Control.
                } else if ip.is_ipv6() && is_private(&ip) {
                    // Google Cloud Run uses NAT with IPv6 Unique
                    // Local Addresses to provide IPv6 connectivity.
                    ula6.push(ip);
                } else if ip.is_ipv4() {
                    regular4.push(ip);
                } else {
                    regular6.push(ip);
                }
            }
        }

        if regular4.is_empty() && regular6.is_empty() {
            // if we have no usable IP addresses then be willing to accept
            // addresses we otherwise wouldn't, like:
            //   + 169.254.x.x (AWS Lambda uses NAT with these)
            //   + IPv6 ULA (Google Cloud Run uses these with address translation)
            regular4 = linklocal4;
            regular6 = ula6;
        }
        let mut regular = regular4;
        regular.extend(regular6);

        regular.sort();
        loopback.sort();

        LocalAddresses { loopback, regular }
    }
}

/// Network interface.
#[derive(Debug, Clone)]
pub struct Interface {
    /// The name of the interface.
    pub name: String,
    /// List of available [IpAddr]s.
    pub addrs: Vec<IpAddr>,
    /// Is the interface up?
    pub is_up: bool,
    /// Is this this a loopback interface?
    pub is_loopback: bool,
}

#[cfg(not(target_os = "android"))]
fn get_interfaces() -> Vec<Interface> {
    let ifaces = default_net::interface::get_interfaces();
    ifaces
        .into_iter()
        .map(|i| Interface {
            addrs: i
                .ipv4
                .iter()
                .map(|a| IpAddr::V4(a.addr))
                .chain(i.ipv6.iter().map(|a| IpAddr::V6(a.addr)))
                .collect(),
            is_up: is_up(&i),
            is_loopback: is_loopback(&i),
            name: i.name,
        })
        .collect()
}

#[cfg(not(target_os = "android"))]
const fn is_up(interface: &default_net::Interface) -> bool {
    interface.flags & IFF_UP != 0
}

#[cfg(not(target_os = "android"))]
const fn is_loopback(interface: &default_net::Interface) -> bool {
    interface.flags & IFF_LOOPBACK != 0
}

/// Reports whether ip is a private address, according to RFC 1918
/// (IPv4 addresses) and RFC 4193 (IPv6 addresses). That is, it reports whether
/// ip is in 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or fc00::/7.
fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            // RFC 1918 allocates 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 as
            // private IPv4 address subnets.
            let octets = ip.octets();
            octets[0] == 10
                || (octets[0] == 172 && octets[1] & 0xf0 == 16)
                || (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(ip) => is_private_v6(ip),
    }
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    // RFC 4193 allocates fc00::/7 as the unique local unicast IPv6 address subnet.
    ip.octets()[0] & 0xfe == 0xfc
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => is_unicast_link_local(ip),
    }
}

// TODO: replace with IpAddr::to_canoncial once stabilized.
fn to_canonical(ip: IpAddr) -> IpAddr {
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
const fn is_unicast_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(target_os = "android")]
fn get_interfaces() -> Vec<Interface> {
    java_sadness().unwrap_or_default()
}

#[cfg(target_os = "android")]
fn java_sadness() -> anyhow::Result<Vec<Interface>> {
    use j4rs::JvmBuilder;

    let jvm = JvmBuilder::new().build()?;

    let network_interfaces = jvm.invoke_static(
        "java.net.NetworkInterface",
        "getNetworkInterfaces",
        &Vec::new(),
    )?;

    let mut interface_list = Vec::new();
    loop {
        let has_more = jvm.invoke(&network_interfaces, "hasMoreElements", &Vec::new())?;
        let has_more: bool = jvm.to_rust(has_more)?;
        if !has_more {
            break;
        }

        let interface = jvm.invoke(&network_interfaces, "nextElement", &Vec::new())?;
        let interface = jvm.cast(&interface, "java.net.NetworkInterface")?;
        let interface_name = jvm.invoke(&interface, "getDisplayName", &Vec::new())?;
        let interface_name: String = jvm.to_rust(interface_name)?;
        let is_loopback = jvm.invoke(&interface, "isLoopback", &Vec::new())?;
        let is_loopback: bool = jvm.to_rust(is_loopback)?;
        let is_up = jvm.invoke(&interface, "isUp", &Vec::new())?;
        let is_up: bool = jvm.to_rust(is_up)?;

        let ips = jvm.invoke(&interface, "getInetAddresses", &Vec::new())?;
        let mut addrs = Vec::new();
        loop {
            let has_more = jvm.invoke(&ips, "hasMoreElements", &Vec::new())?;
            let has_more: bool = jvm.to_rust(has_more)?;
            if !has_more {
                break;
            }
            let ip = jvm.invoke(&ips, "nextElement", &Vec::new())?;
            let ip = jvm.cast(&ip, "java.net.InetAddress")?;
            let ip_string = jvm.invoke(&ip, "toString", &Vec::new())?;
            let ip_string: String = jvm.to_rust(ip_string)?;

            // String format is like this
            // /fe80:0:0:0:7823:59ed:8756:ac96%wlp74s0
            // /192.168.178.89

            let ip_str = ip_string
                .trim_start_matches('/')
                .split('%')
                .next()
                .ok_or_else(|| anyhow::anyhow!("invalid ip addr format: {}", ip_string))?;
            let ip: IpAddr = ip_str.parse()?;
            addrs.push(ip);
        }

        interface_list.push(Interface {
            name: interface_name,
            addrs,
            is_up,
            is_loopback,
        });
    }

    Ok(interface_list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_addresses() {
        let addrs = LocalAddresses::new();
        dbg!(&addrs);
        assert!(!addrs.loopback.is_empty());
        assert!(!addrs.regular.is_empty());
    }

    #[test]
    #[cfg(target_os = "android")]
    fn test_java_sadness() {
        let interfaces = java_sadness().unwrap();
        dbg!(&interfaces);
        assert!(!interfaces.is_empty());
    }
}
