//! Contains helpers for looking up system network interfaces.

use std::{collections::HashMap, net::IpAddr};

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
pub(super) mod bsd;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

pub use default_net::ip::{Ipv4Net, Ipv6Net};

use crate::net::ip::{is_loopback, is_private_v6, is_up};

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
use self::bsd::default_route;
#[cfg(any(target_os = "linux", target_os = "android"))]
use self::linux::default_route;
#[cfg(target_os = "windows")]
use self::windows::default_route;

/// Represents a network interface.
#[derive(Debug)]
pub struct Interface {
    iface: default_net::interface::Interface,
}

impl PartialEq for Interface {
    fn eq(&self, other: &Self) -> bool {
        self.iface.index == other.iface.index
            && self.iface.name == other.iface.name
            && self.iface.flags == other.iface.flags
            && self.iface.mac_addr.as_ref().map(|a| a.octets())
                == other.iface.mac_addr.as_ref().map(|a| a.octets())
    }
}

impl Eq for Interface {}

impl Interface {
    /// Does this represent the loopback interface?
    pub fn is_loopback(&self) -> bool {
        is_loopback(&self.iface)
    }

    /// Is this interface up?
    pub fn is_up(&self) -> bool {
        is_up(&self.iface)
    }

    /// The name of the interface.
    pub fn name(&self) -> &str {
        &self.iface.name
    }

    /// A list of all ip addresses of this interface.
    pub fn addrs(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.iface
            .ipv4
            .iter()
            .cloned()
            .map(IpNet::V4)
            .chain(self.iface.ipv6.iter().cloned().map(IpNet::V6))
    }

    /// Creates a fake interface for usage in tests.
    ///
    /// Sometimes tests want to be deterministic, e.g. [`ProbePlan`] tests rely on the
    /// interface state.  This allows tests to be independent of the host interfaces.
    ///
    /// It is rather possible that we'll want more variations of this in the future, feel
    /// free to add parameters or different alternative constructors.
    ///
    /// [`ProbePlan`]: crate::netcheck::reportgen::probes::ProbePlan
    #[cfg(test)]
    pub(crate) fn fake() -> Self {
        use std::net::Ipv4Addr;

        use default_net::{interface::InterfaceType, mac::MacAddr, Gateway};

        Self {
            iface: default_net::Interface {
                index: 2,
                name: String::from("wifi0"),
                friendly_name: None,
                description: None,
                if_type: InterfaceType::Ethernet,
                mac_addr: Some(MacAddr::new(2, 3, 4, 5, 6, 7)),
                ipv4: vec![Ipv4Net {
                    addr: Ipv4Addr::from([192, 168, 0, 189]),
                    prefix_len: 24,
                    netmask: Ipv4Addr::from([255, 255, 255, 0]),
                }],
                ipv6: vec![],
                flags: 69699,
                transmit_speed: None,
                receive_speed: None,
                gateway: Some(Gateway {
                    mac_addr: MacAddr::new(2, 3, 4, 5, 6, 8),
                    ip_addr: IpAddr::V4(Ipv4Addr::from([192, 168, 0, 1])),
                }),
            },
        }
    }
}

/// Structure of an IP network, either IPv4 or IPv6.
#[derive(Clone, Debug)]
pub enum IpNet {
    /// Structure of IPv4 Network.
    V4(Ipv4Net),
    /// Structure of IPv6 Network.
    V6(Ipv6Net),
}

impl PartialEq for IpNet {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (IpNet::V4(a), IpNet::V4(b)) => {
                a.addr == b.addr && a.prefix_len == b.prefix_len && a.netmask == b.netmask
            }
            (IpNet::V6(a), IpNet::V6(b)) => {
                a.addr == b.addr && a.prefix_len == b.prefix_len && a.netmask == b.netmask
            }
            _ => false,
        }
    }
}
impl Eq for IpNet {}

impl IpNet {
    /// The IP address of this structure.
    pub fn addr(&self) -> IpAddr {
        match self {
            IpNet::V4(a) => IpAddr::V4(a.addr),
            IpNet::V6(a) => IpAddr::V6(a.addr),
        }
    }
}

/// Intended to store the state of the machine's network interfaces, routing table, and
/// other network configuration. For now it's pretty basic.
#[derive(Debug, PartialEq, Eq)]
pub struct State {
    /// Maps from an interface name interface.
    pub interfaces: HashMap<String, Interface>,

    /// Whether this machine has an IPv6 Global or Unique Local Address
    /// which might provide connectivity.
    pub have_v6: bool,

    /// Whether the machine has some non-localhost, non-link-local IPv4 address.
    pub have_v4: bool,

    //// Whether the current network interface is considered "expensive", which currently means LTE/etc
    /// instead of Wifi. This field is not populated by `get_state`.
    pub is_expensive: bool,

    /// The interface name for the machine's default route.
    ///
    /// It is not yet populated on all OSes.
    ///
    /// When set, its value is the map key into `interface` and `interface_ips`.
    pub default_route_interface: Option<String>,

    /// The HTTP proxy to use, if any.
    pub http_proxy: Option<String>,

    /// The URL to the Proxy Autoconfig URL, if applicable.
    pub pac: Option<String>,
}

impl State {
    /// Returns the state of all the current machine's network interfaces.
    ///
    /// It does not set the returned `State.is_expensive`. The caller can populate that.
    pub async fn new() -> Self {
        let mut interfaces = HashMap::new();
        let mut have_v6 = false;
        let mut have_v4 = false;

        let ifaces = default_net::interface::get_interfaces();
        for iface in ifaces {
            let ni = Interface { iface };
            let if_up = ni.is_up();
            let name = ni.iface.name.clone();
            let pfxs: Vec<_> = ni.addrs().collect();

            if if_up {
                for pfx in &pfxs {
                    if pfx.addr().is_loopback() {
                        continue;
                    }
                    have_v6 |= is_usable_v6(&pfx.addr());
                    have_v4 |= is_usable_v4(&pfx.addr());
                }
            }

            interfaces.insert(name, ni);
        }

        let default_route_interface = default_route_interface().await;

        State {
            interfaces,
            have_v4,
            have_v6,
            is_expensive: false,
            default_route_interface,
            http_proxy: None,
            pac: None,
        }
    }

    /// Creates a fake interface state for usage in tests.
    ///
    /// Sometimes tests want to be deterministic, e.g. [`ProbePlan`] tests rely on the
    /// interface state.  This allows tests to be independent of the host interfaces.
    ///
    /// It is rather possible that we'll want more variations of this in the future, feel
    /// free to add parameters or different alternative constructors.
    ///
    /// [`ProbePlan`]: crate::netcheck::reportgen::probes::ProbePlan
    #[cfg(test)]
    pub(crate) fn fake() -> Self {
        let fake = Interface::fake();
        let ifname = fake.iface.name.clone();
        Self {
            interfaces: [(ifname.clone(), fake)].into_iter().collect(),
            have_v6: false,
            have_v4: true,
            is_expensive: false,
            default_route_interface: Some(ifname),
            http_proxy: None,
            pac: None,
        }
    }

    /// Is a PAC set?
    pub fn has_pac(&self) -> bool {
        self.pac.is_some()
    }

    /// Reports whether any interface has the provided IP address.
    pub fn has_ip(&self, ip: &IpAddr) -> bool {
        for pv in self.interfaces.values() {
            for p in pv.addrs() {
                match (p, ip) {
                    (IpNet::V4(a), IpAddr::V4(b)) => {
                        if &a.addr == b {
                            return true;
                        }
                    }
                    (IpNet::V6(a), IpAddr::V6(b)) => {
                        if &a.addr == b {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Reports whether any interface seems like it has internet access.
    pub fn any_interface_up(&self) -> bool {
        self.have_v4 || self.have_v6
    }
}

/// Reports whether ip is a usable IPv4 address which could
/// conceivably be used to get Internet connectivity. Globally routable and
/// private IPv4 addresses are always Usable, and link local 169.254.x.x
/// addresses are in some environments.
fn is_usable_v4(ip: &IpAddr) -> bool {
    if !ip.is_ipv4() || ip.is_loopback() {
        return false;
    }

    true
}

/// Reports whether ip is a usable IPv6 address which could
/// conceivably be used to get Internet connectivity. Globally routable
/// IPv6 addresses are always Usable, and Unique Local Addresses
/// (fc00::/7) are in some environments used with address translation.
fn is_usable_v6(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(ip) => {
            // V6 Global1 2000::/3
            let mask: u16 = 0b1110_0000_0000_0000;
            let base: u16 = 0x2000;
            let segment1 = ip.segments()[0];
            if (base & mask) == (segment1 & mask) {
                return true;
            }

            is_private_v6(ip)
        }
        IpAddr::V4(_) => false,
    }
}

/// The details about a default route.
#[derive(Debug, Clone)]
pub struct DefaultRouteDetails {
    /// The interface name.
    /// It's like "eth0" (Linux), "Ethernet 2" (Windows), "en0" (macOS).
    pub interface_name: String,

    /// Ppopulated on Windows at least. Longer description of the interface.
    pub interface_description: Option<String>,

    /// The index of the interface, `0` means not populated.
    pub interface_index: u32,
}

impl DefaultRouteDetails {
    /// Reads the default route from the current system and returns the details.
    pub async fn new() -> Option<Self> {
        default_route().await
    }
}

/// Like `DefaultRoutDetails::new` but only returns the interface name.
pub async fn default_route_interface() -> Option<String> {
    DefaultRouteDetails::new().await.map(|v| v.interface_name)
}

/// Likely IPs of the residentla router, and the ip address of the current
/// machine using it.
#[derive(Debug, Clone)]
pub struct HomeRouter {
    /// Ip of the router.
    pub gateway: IpAddr,
    /// Our local Ip if known.
    pub my_ip: Option<IpAddr>,
}

impl HomeRouter {
    /// Returns the likely IP of the residential router, which will always
    /// be a private address, if found.
    /// In addition, it returns the IP address of the current machine on
    /// the LAN using that gateway.
    /// This is used as the destination for UPnP, NAT-PMP, PCP, etc queries.
    pub fn new() -> Option<Self> {
        let gateway = Self::get_default_gateway()?;
        let my_ip = default_net::interface::get_local_ipaddr();

        Some(HomeRouter { gateway, my_ip })
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos",
        target_os = "ios"
    ))]
    fn get_default_gateway() -> Option<IpAddr> {
        // default_net doesn't work yet
        // See: https://github.com/shellrow/default-net/issues/34
        bsd::likely_home_router()
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "windows"))]
    fn get_default_gateway() -> Option<IpAddr> {
        let gateway = default_net::get_default_gateway().ok()?;
        Some(gateway.ip_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_route() {
        let default_route = DefaultRouteDetails::new()
            .await
            .expect("missing default route");
        println!("default_route: {:#?}", default_route);
    }

    #[tokio::test]
    async fn test_likely_home_router() {
        let home_router = HomeRouter::new().expect("missing home router");
        println!("home router: {:#?}", home_router);
    }
}
