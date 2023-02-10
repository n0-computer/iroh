//! Contains helpers for looking up system network interfaces.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
};

use default_net::ip::{Ipv4Net, Ipv6Net};

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;

const fn is_up(interface: &default_net::Interface) -> bool {
    interface.flags & IFF_UP != 0
}

const fn is_loopback(interface: &default_net::Interface) -> bool {
    interface.flags & IFF_LOOPBACK != 0
}

/// Returns the machine's IP addresses, separated by
/// whether they're loopback addresses. If there are no regular addresses
/// it will return any IPv4 linklocal or IPv6 unique local addresses because we
/// know of environments where these are used with NAT to provide connectivity.
fn local_addresses() -> (Vec<IpAddr>, Vec<IpAddr>) {
    // TODO: don't serve interface addresses that we are routing

    let ifaces = default_net::interface::get_interfaces();
    let mut loopback = Vec::new();
    let mut regular4 = Vec::new();
    let mut regular6 = Vec::new();
    let mut linklocal4 = Vec::new();
    let mut ula6 = Vec::new();

    for iface in ifaces {
        if !is_up(&iface) {
            // Skip down interfaces and ones that are
            // problematic that we don't want to try to
            // send Tailscale traffic over.
            continue;
        }
        let ifc_is_loopback = is_loopback(&iface);
        let addrs = iface
            .ipv4
            .iter()
            .map(|a| IpAddr::V4(a.addr))
            .chain(iface.ipv6.iter().map(|a| IpAddr::V6(a.addr)));

        for ip in addrs {
            // ip = ip.Unmap()

            if ip.is_loopback() || ifc_is_loopback {
                loopback.push(ip);
            } else if let IpAddr::V4(ip4) = ip {
                if ip4.is_link_local() {
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
        // TODO: hostinfo
        // if hostinfo.GetEnvType() == hostinfo.AWSLambda {
        // regular4 = linklocal4
        // }
        regular6 = ula6;
    }
    let mut regular = regular4;
    regular.extend(regular6);

    regular.sort();
    loopback.sort();

    (regular, loopback)
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
    pub fn is_loopback(&self) -> bool {
        is_loopback(&self.iface)
    }

    pub fn is_up(&self) -> bool {
        is_up(&self.iface)
    }

    pub fn addrs(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.iface
            .ipv4
            .iter()
            .cloned()
            .map(IpNet::V4)
            .chain(self.iface.ipv6.iter().cloned().map(IpNet::V6))
    }
}

#[derive(Clone, Debug)]
pub enum IpNet {
    V4(Ipv4Net),
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
    pub fn addr(&self) -> IpAddr {
        match self {
            IpNet::V4(a) => IpAddr::V4(a.addr),
            IpNet::V6(a) => IpAddr::V6(a.addr),
        }
    }
}

/// Intended to store the state of the machine's network interfaces,
/// routing table, and other network configuration.
/// For now it's pretty basic.
#[derive(Debug)]
pub struct State {
    /// Maps from an interface name to the IP addresses configured on that interface.
    pub interface_ips: HashMap<String, Vec<IpNet>>,
    pub interface: HashMap<String, Interface>,

    /// Whether this machine has an IPv6 Global or Unique Local Address
    /// which might provide connectivity.
    pub have_v6: bool,

    /// Whether the machine has some non-localhost, non-link-local IPv4 address.
    pub have_v4: bool,

    //// Whether the current network interface is considered "expensive", which currently means LTE/etc
    /// instead of Wifi. This field is not populated by `get_state`.
    pub is_expensive: bool,

    /// DefaultRouteInterface is the interface name for the
    /// machine's default route.
    ///
    /// It is not yet populated on all OSes.
    ///
    /// When set, its value is the map key into `interface` and `interface_ips`.
    default_route_interface: Option<String>,

    /// The HTTP proxy to use, if any.
    pub http_proxy: Option<String>,

    /// The URL to the Proxy Autoconfig URL, if applicable.
    pub pac: Option<String>,
}

// An InterfaceFilter indicates whether EqualFiltered should use i when deciding whether two States are equal.
// ips are all the IPPrefixes associated with i.
// type InterfaceFilter func(i Interface, ips []netip.Prefix) bool

// An IPFilter indicates whether EqualFiltered should use ip when deciding whether two States are equal.
// ip is an ip address associated with some interface under consideration.
// type IPFilter func(ip netip.Addr) bool

impl State {
    pub fn has_pac(&self) -> bool {
        self.pac.is_some()
    }

    /// Reports whether s and s2 are equal,
    /// considering only interfaces in s for which filter returns true,
    /// and considering only IPs for those interfaces for which filterIP returns true.
    fn equal_filtered<F, G>(&self, s2: &Self, use_interface: F, use_ip: G) -> bool
    where
        F: Fn(&Interface, &[IpNet]) -> bool,
        G: Fn(IpAddr) -> bool,
    {
        if self.have_v6 != s2.have_v6
            || self.have_v4 != s2.have_v4
            || self.is_expensive != s2.is_expensive
            || self.default_route_interface != s2.default_route_interface
            || self.http_proxy != s2.http_proxy
            || self.pac != s2.pac
        {
            return false;
        }
        for (iname, i) in &self.interface {
            if let Some(ips) = self.interface_ips.get(iname) {
                if !use_interface(i, ips) {
                    continue;
                }
                let i2 = s2.interface.get(iname);
                if i2.is_none() {
                    return false;
                }
                let i2 = i2.unwrap();
                let ips2 = s2.interface_ips.get(iname);
                if ips2.is_some() {
                    return false;
                }
                let ips2 = ips2.unwrap();
                if i != i2 || !prefixes_equal_filtered(ips, ips2, &use_ip) {
                    return false;
                }
            }
        }
        true
    }

    /// Reports whether any interface has the provided IP address.
    fn has_ip(&self, ip: &IpAddr) -> bool {
        for (_, pv) in &self.interface_ips {
            for p in pv {
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

    // Reports whether any interface seems like it has Internet access.
    pub fn any_interface_up(&self) -> bool {
        self.have_v4 || self.have_v6
    }

    /// Returns the state of all the current machine's network interfaces.
    ///
    /// It does not set the returned `State.is_expensive`. The caller can populate that.
    pub fn new() -> Self {
        let mut interface_ips = HashMap::new();
        let mut interface = HashMap::new();
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

            interface.insert(name.clone(), ni);
            interface_ips.insert(name, pfxs);
        }

        let default_route_interface = default_route_interface();

        State {
            interface_ips,
            interface,
            have_v4,
            have_v6,
            is_expensive: false,
            default_route_interface,
            http_proxy: None,
            pac: None,
        }
    }
}

fn prefixes_equal_filtered<F>(a: &[IpNet], b: &[IpNet], use_ip: F) -> bool
where
    F: Fn(IpAddr) -> bool,
{
    if a.len() != b.len() {
        return false;
    }
    for (a, b) in a.iter().zip(b.iter()) {
        let use_a = use_ip(a.addr());
        let use_b = use_ip(b.addr());
        if use_a != use_b {
            return false;
        }
        if use_a && a.addr() != b.addr() {
            return false;
        }
    }

    true
}

// An InterfaceFilter that reports whether i is an interesting interface.
// An interesting interface if it routes interesting IP addresses.
// See `use_interesting_ips` for the definition of an interesting IP address.
pub fn use_interesting_interfaces(_i: &Interface, ips: &[IpNet]) -> bool {
    any_interesting_ip(ips)
}

// An IPFilter that reports whether ip is an interesting IP address.
// An IP address is interesting if it is neither a loopback nor a link local unicast IP address.
fn use_interesting_ips(ip: &IpNet) -> bool {
    is_interesting_ip(&ip.addr())
}

// An InterfaceFilter that includes all interfaces.
fn use_all_interfaces(_i: &Interface, _ips: &[IpNet]) -> bool {
    true
}

// An IPFilter that includes all IPs.
fn use_all_ips(_ip: &IpNet) -> bool {
    true
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
            if matches!(ip.segments(), [0x2000, _, _, _, _, _, _, _]) {
                return true;
            }

            is_private_v6(ip)
        }
        IpAddr::V4(_) => false,
    }
}

/// Reports whether pfxs contains any IP that matches `is_interesting_ip`.
fn any_interesting_ip(pfxs: &[IpNet]) -> bool {
    pfxs.iter().any(|pfx| is_interesting_ip(&pfx.addr()))
}

/// Reports whether ip is an interesting IP that we
/// should log in interfaces.State logging. We don't need to show
/// localhost or link-local addresses.
fn is_interesting_ip(ip: &IpAddr) -> bool {
    if ip.is_loopback() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                return false;
            }
        }
        IpAddr::V6(v6) => {
            // TODO: use once stabilized
            // if v6.is_unicast_link_local() {
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return false;
            }
        }
    }
    true
}

/// The details about a default route.
pub struct DefaultRouteDetails {
    /// The interface name. It must always be populated.
    /// It's like "eth0" (Linux), "Ethernet 2" (Windows), "en0" (macOS).
    pub interface_name: String,

    /// Ppopulated on Windows at least. It's a
    /// longer description, like "Red Hat VirtIO Ethernet Adapter".
    pub interface_description: Option<String>,

    /// Like net.Interface.Index. Zero means not populated.
    pub interface_index: u32,
}

impl DefaultRouteDetails {
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos",
        target_os = "ios"
    ))]
    pub fn new() -> Option<Self> {
        bsd::default_route()
    }

    #[cfg(target_os = "linux")]
    pub fn new() -> Option<Self> {
        todo!()
    }
}

/// Like `DefaultRoutDetails::new` but only returns the interface name.
pub fn default_route_interface() -> Option<String> {
    DefaultRouteDetails::new().map(|v| v.interface_name)
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
mod bsd {
    //! Baed on  https://cs.opensource.google/go/x/net/+/master:route

    use std::{
        collections::HashMap,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use super::DefaultRouteDetails;

    pub fn default_route() -> Option<DefaultRouteDetails> {
        let idx = default_route_interface_index()?;
        let interfaces = default_net::get_interfaces();
        let iface = interfaces.into_iter().find(|i| i.index == idx)?;

        Some(DefaultRouteDetails {
            interface_index: idx,
            interface_name: iface.name,
            interface_description: None,
        })
    }

    /// Returns the index of the network interface that
    /// owns the default route. It returns the first IPv4 or IPv6 default route it
    /// finds (it does not prefer one or the other).
    fn default_route_interface_index() -> Option<u32> {
        // $ netstat -nr
        // Routing tables
        // Internet:
        // Destination        Gateway            Flags        Netif Expire
        // default            10.0.0.1           UGSc           en0         <-- want this one
        // default            10.0.0.1           UGScI          en1

        // From man netstat:
        // U       RTF_UP           Route usable
        // G       RTF_GATEWAY      Destination requires forwarding by intermediary
        // S       RTF_STATIC       Manually added
        // c       RTF_PRCLONING    Protocol-specified generate new routes on use
        // I       RTF_IFSCOPE      Route is associated with an interface scope

        let rib = fetch_routing_table()?;
        let msgs = parse_routing_table(&rib)?;
        for rm in msgs {
            if is_default_gateway(&rm) {
                return Some(rm.index as u32);
            }
        }
        None
    }

    const V4_DEFAULT: [u8; 4] = [0u8; 4];
    const V6_DEFAULT: [u8; 16] = [0u8; 16];

    fn is_default_gateway(rm: &RouteMessage) -> bool {
        if rm.flags & libc::RTF_GATEWAY as u32 == 0 {
            return false;
        }

        if rm.flags & libc::RTF_IFSCOPE as u32 != 0 {
            return false;
        }

        // Addrs is [RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, ...]
        if rm.addrs.len() <= libc::RTAX_NETMASK as usize {
            return false;
        }

        let dst = rm.addrs.get(libc::RTAX_DST as usize);
        let netmask = rm.addrs.get(libc::RTAX_NETMASK as usize);
        if dst.is_none() || netmask.is_none() {
            return false;
        }
        let dst = dst.unwrap();
        let netmask = netmask.unwrap();

        match (dst, netmask) {
            (Addr::Inet4 { ip: dst }, Addr::Inet4 { ip: netmask }) => {
                if dst.octets() == V4_DEFAULT && netmask.octets() == V4_DEFAULT {
                    return true;
                }
            }
            _ => {}
        }

        match (dst, netmask) {
            (Addr::Inet6 { ip: dst, .. }, Addr::Inet6 { ip: netmask, .. }) => {
                if dst.octets() == V6_DEFAULT && netmask.octets() == V6_DEFAULT {
                    return true;
                }
            }
            _ => {}
        }

        false
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd",))]
    fn fetch_routing_table() -> Option<Vec<u8>> {
        fetch_rib(libc::AF_UNSPEC, libc::NET_RT_DUMP, 0).ok()
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd",))]
    fn parse_routing_table(rib: &[u8]) -> Option<Vec<RouteMessage>> {
        parse_rib(libc::NET_RT_IFLIST, rib).ok()
    }

    #[cfg(any(target_os = "macos", target_os = "ios",))]
    fn fetch_routing_table() -> Option<Vec<u8>> {
        const NET_RT_DUMP2: i32 = 7;
        fetch_rib(libc::AF_UNSPEC, NET_RT_DUMP2, 0).ok()
    }

    #[cfg(any(target_os = "macos", target_os = "ios",))]
    fn parse_routing_table(rib: &[u8]) -> Option<Vec<RouteMessage>> {
        parse_rib(libc::NET_RT_IFLIST2, rib).ok()
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const fn is_valid_rib_type(typ: RIBType) -> bool {
        const NET_RT_STAT: RIBType = 4;
        const NET_RT_TRASH: RIBType = 5;
        if typ == NET_RT_STAT || typ == NET_RT_TRASH {
            return false;
        }
        true
    }

    #[cfg(any(target_os = "free", target_os = "netbsd"))]
    const fn is_valid_rib_type(typ: RIBType) -> bool {
        true
    }

    #[cfg(target_os = "openbsd")]
    const fn is_valid_rib_type(_typ: RIBType) -> bool {
        if typ == libc::NET_RT_STATS || typ == libc::NET_RT_TABLE {
            return false;
        }
        true
    }

    #[derive(Debug, Copy, Clone)]
    struct WireFormat {
        /// offset of header extension
        ext_off: usize,
        /// offset of message body
        body_off: usize,
        typ: MessageType,
    }

    impl WireFormat {
        #[cfg(any(
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "macos",
            target_os = "ios"
        ))]
        fn parse(&self, _typ: RIBType, data: &[u8]) -> Result<Option<RouteMessage>, RouteError> {
            match self.typ {
                MessageType::Route => {
                    if data.len() < self.body_off {
                        return Err(RouteError::MessageTooShort);
                    }
                    let l = u16::from_ne_bytes(data[..2].try_into().unwrap());
                    if data.len() < l as usize {
                        return Err(RouteError::InvalidMessage);
                    }
                    let addrs = parse_addrs(
                        u32::from_ne_bytes(data[12..16].try_into().unwrap()) as _,
                        parse_kernel_inet_addr,
                        &data[self.body_off..],
                    )?;
                    let mut m = RouteMessage {
                        version: data[2] as _,
                        r#type: data[3] as _,
                        flags: u32::from_ne_bytes(data[8..12].try_into().unwrap()),
                        index: u16::from_ne_bytes(data[4..6].try_into().unwrap()),
                        id: u32::from_ne_bytes(data[16..20].try_into().unwrap()) as _,
                        seq: u32::from_ne_bytes(data[20..24].try_into().unwrap()),
                        ext_off: self.ext_off,
                        error: None,
                        addrs,
                    };
                    let errno = u32::from_ne_bytes(data[28..32].try_into().unwrap());
                    if errno != 0 {
                        m.error = Some(std::io::Error::from_raw_os_error(errno as _));
                    }

                    Ok(Some(m))
                }
                MessageType::Interface => {
                    todo!()
                }
                MessageType::InterfaceAddr => {
                    todo!()
                }
                MessageType::InterfaceMulticastAddr => {
                    todo!()
                }
            }
        }

        #[cfg(any(target_os = "openbsd"))]
        fn parse(&self, typ: RIBType, data: &[u8]) -> Result<Option<RouteMessage>, RouteError> {
            // https://cs.opensource.google/go/x/net/+/master:route/route_openbsd.go
            todo!()
        }
    }

    #[derive(Debug, Copy, Clone)]
    enum MessageType {
        Route,
        Interface,
        InterfaceAddr,
        InterfaceMulticastAddr,
    }

    use once_cell::sync::Lazy;
    static ROUTING_STACK: Lazy<RoutingStack> = Lazy::new(probe_routing_stack);

    // Hardcoded based on the generated values here: https://cs.opensource.google/go/x/net/+/master:route/zsys_darwin.go
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofIfMsghdrDarwin15: usize = 0x70;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofIfaMsghdrDarwin15: usize = 0x14;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofIfmaMsghdrDarwin15: usize = 0x10;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofIfMsghdr2Darwin15: usize = 0xa0;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofIfmaMsghdr2Darwin15: usize = 0x14;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofIfDataDarwin15: usize = 0x60;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofIfData64Darwin15: usize = 0x80;

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofRtMsghdrDarwin15: usize = 0x5c;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofRtMsghdr2Darwin15: usize = 0x5c;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofRtMetricsDarwin15: usize = 0x38;

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofSockaddrStorage: usize = 0x80;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofSockaddrInet: usize = 0x10;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const sizeofSockaddrInet6: usize = 0x1c;

    struct RoutingStack {
        rtm_version: i32,
        kernel_align: usize,
        wire_formats: HashMap<i32, WireFormat>,
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn probe_routing_stack() -> RoutingStack {
        let rtm_version = libc::RTM_VERSION;

        let rtm = WireFormat {
            ext_off: 36,
            body_off: sizeofRtMsghdrDarwin15,
            typ: MessageType::Route,
        };
        let rtm2 = WireFormat {
            ext_off: 36,
            body_off: sizeofRtMsghdr2Darwin15,
            typ: MessageType::Route,
        };
        let ifm = WireFormat {
            ext_off: 16,
            body_off: sizeofIfMsghdrDarwin15,
            typ: MessageType::Interface,
        };
        let ifm2 = WireFormat {
            ext_off: 32,
            body_off: sizeofIfMsghdr2Darwin15,
            typ: MessageType::Interface,
        };
        let ifam = WireFormat {
            ext_off: sizeofIfaMsghdrDarwin15,
            body_off: sizeofIfaMsghdrDarwin15,
            typ: MessageType::InterfaceAddr,
        };
        let ifmam = WireFormat {
            ext_off: sizeofIfmaMsghdrDarwin15,
            body_off: sizeofIfmaMsghdrDarwin15,
            typ: MessageType::InterfaceMulticastAddr,
        };
        let ifmam2 = WireFormat {
            ext_off: sizeofIfmaMsghdr2Darwin15,
            body_off: sizeofIfmaMsghdr2Darwin15,
            typ: MessageType::InterfaceMulticastAddr,
        };

        let wire_formats = [
            (libc::RTM_ADD, rtm),
            (libc::RTM_DELETE, rtm),
            (libc::RTM_CHANGE, rtm),
            (libc::RTM_GET, rtm),
            (libc::RTM_LOSING, rtm),
            (libc::RTM_REDIRECT, rtm),
            (libc::RTM_MISS, rtm),
            (libc::RTM_LOCK, rtm),
            (libc::RTM_RESOLVE, rtm),
            (libc::RTM_NEWADDR, ifam),
            (libc::RTM_DELADDR, ifam),
            (libc::RTM_IFINFO, ifm),
            (libc::RTM_NEWMADDR, ifmam),
            (libc::RTM_DELMADDR, ifmam),
            (libc::RTM_IFINFO2, ifm2),
            (libc::RTM_NEWMADDR2, ifmam2),
            (libc::RTM_GET2, rtm2),
        ]
        .into_iter()
        .collect();

        RoutingStack {
            rtm_version,
            wire_formats,
            kernel_align: 4,
        }
    }

    /// Parses b as a routing information base and returns a list of routing messages.
    fn parse_rib(typ: RIBType, data: &[u8]) -> Result<Vec<RouteMessage>, RouteError> {
        if !is_valid_rib_type(typ) {
            panic!("unsupported");
            // return nil, errUnsupportedMessage
        }

        let mut msgs = Vec::new();
        let mut nmsgs = 0;
        let mut nskips = 0;
        let mut b = data;

        while b.len() > 4 {
            nmsgs += 1;
            let l = u16::from_ne_bytes(b[..2].try_into().unwrap());
            if l == 0 {
                return Err(RouteError::InvalidMessage);
            }
            if b.len() < l as usize {
                return Err(RouteError::MessageTooShort);
            }
            if b[2] as i32 != ROUTING_STACK.rtm_version {
                // b = b[l:];
                continue;
            }
            match ROUTING_STACK.wire_formats.get(&(b[3] as i32)) {
                Some(w) => {
                    let m = w.parse(typ, &b[..l as usize])?;
                    match m {
                        Some(m) => {
                            msgs.push(m);
                        }
                        None => {
                            nskips += 1;
                        }
                    }
                }
                None => {
                    nskips += 1;
                }
            }
            b = &b[l as usize..];
        }

        // We failed to parse any of the messages - version mismatch?
        if nmsgs != msgs.len() + nskips {
            return Err(RouteError::MessageMismatch);
        }

        Ok(msgs)
    }

    /// A RouteMessage represents a message conveying an address prefix, a
    /// nexthop address and an output interface.
    ///
    /// Unlike other messages, this message can be used to query adjacency
    /// information for the given address prefix, to add a new route, and
    /// to delete or modify the existing route from the routing information
    /// base inside the kernel by writing and reading route messages on a
    /// routing socket.
    ///
    /// For the manipulation of routing information, the route message must
    /// contain appropriate fields that include:
    ///
    ///	Version       = <must be specified>
    ///	Type          = <must be specified>
    ///	Flags         = <must be specified>
    ///	Index         = <must be specified if necessary>
    ///	ID            = <must be specified>
    ///	Seq           = <must be specified>
    ///	Addrs         = <must be specified>
    #[derive(Debug)]
    struct RouteMessage {
        /// message version
        pub version: isize,
        /// message type
        pub r#type: isize,
        /// route flags
        pub flags: u32,
        /// interface index when attached
        pub index: u16,
        /// sender's identifier; usually process ID
        pub id: libc::uintptr_t,
        /// sequence number
        pub seq: u32,
        // error on requested operation
        pub error: Option<std::io::Error>,
        // addresses
        pub addrs: Vec<Addr>,
        // offset of header extension
        ext_off: usize,
        // raw:  []byte // raw message
    }

    /// Represents a type of routing information base.
    type RIBType = i32;

    const RIBTypeRoute: RIBType = libc::NET_RT_DUMP;
    const RIBTypeInterface: RIBType = libc::NET_RT_IFLIST;

    #[derive(Debug, thiserror::Error)]
    enum RouteError {
        #[error("unsupported message")]
        UnsupportedMessage,
        #[error("message mismatch")]
        MessageMismatch,
        #[error("message too short")]
        MessageTooShort,
        #[error("invalid message")]
        InvalidMessage,
        #[error("invalid address")]
        InvalidAddress,
        #[error("short buffer")]
        ShortBuffer,
    }

    /// FetchRIB fetches a routing information base from the operating system.
    ///
    /// The provided af must be an address family.
    ///
    /// The provided arg must be a RIBType-specific argument.
    /// When RIBType is related to routes, arg might be a set of route
    /// flags. When RIBType is related to network interfaces, arg might be
    /// an interface index or a set of interface flags. In most cases, zero
    /// means a wildcard.

    fn fetch_rib(af: i32, typ: RIBType, arg: i32) -> Result<Vec<u8>, RouteError> {
        let mut round = 0;
        loop {
            round += 1;

            let mut mib: [i32; 6] = [libc::CTL_NET, libc::AF_ROUTE, 0, af, typ, arg];
            let mut n: libc::size_t = 0;
            let err = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr() as *mut _,
                    6,
                    std::ptr::null_mut(),
                    &mut n,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if err != 0 {
                panic!("failed {}", err);
                // return nil, os.NewSyscallError("sysctl", err);
            }
            if n == 0 {
                // nothing available
                return Ok(Vec::new());
            }
            let mut b = vec![0u8; n];
            let err = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr() as _,
                    6,
                    b.as_mut_ptr() as _,
                    &mut n,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if err != 0 {
                // If the sysctl failed because the data got larger
                // between the two sysctl calls, try a few times
                // before failing. (golang.org/issue/45736).
                const MAX_TRIES: usize = 3;
                if err == libc::ENOMEM && round < MAX_TRIES {
                    continue;
                }
                panic!("error {}", err);
                // return nil, os.NewSyscallError("sysctl", err);
            }
            return Ok(b);
        }
    }

    /// Represents an address associated with packet routing.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Addr {
        /// Represents a link-layer address.
        Link {
            /// interface index when attached
            index: i32,
            /// interface name when attached
            name: Option<String>,
            /// link-layer address when attached
            addr: Option<Box<[u8]>>,
        },
        /// Represents an internet address for IPv4.
        Inet4 { ip: Ipv4Addr },
        /// Represents an internet address for IPv6.
        Inet6 { ip: Ipv6Addr, zone: u32 },
        /// Represents an address of various operating system-specific features.
        Default {
            af: i32,
            /// raw format of address
            raw: Box<[u8]>,
        },
    }

    impl Addr {
        pub fn family(&self) -> i32 {
            match self {
                Addr::Link { .. } => libc::AF_LINK,
                Addr::Inet4 { .. } => libc::AF_INET,
                Addr::Inet6 { .. } => libc::AF_INET6,
                Addr::Default { af, .. } => *af,
            }
        }
    }

    fn roundup(l: usize) -> usize {
        if l == 0 {
            return ROUTING_STACK.kernel_align;
        }
        let mut x = l + ROUTING_STACK.kernel_align - 1;
        x &= !(ROUTING_STACK.kernel_align - 1);
        x
    }

    fn parse_addrs<F>(attrs: i32, default_fn: F, data: &[u8]) -> Result<Vec<Addr>, RouteError>
    where
        F: Fn(i32, &[u8]) -> Result<(i32, Addr), RouteError>,
    {
        let mut addrs = Vec::with_capacity(libc::RTAX_MAX as usize);
        let af = libc::AF_UNSPEC;

        let mut b = data;
        for i in 0..libc::RTAX_MAX as usize {
            if b.len() < roundup(0) {
                break;
            }

            if attrs & (1 << i) == 0 {
                continue;
            }
            if i <= libc::RTAX_BRD as usize {
                match b[1] as i32 {
                    libc::AF_LINK => {
                        let a = parse_link_addr(b)?;
                        addrs.push(a);
                        let l = roundup(b[0] as usize);
                        if b.len() < l {
                            return Err(RouteError::MessageTooShort);
                        }
                        b = &b[l..];
                    }
                    libc::AF_INET | libc::AF_INET6 => {
                        let af = b[1] as i32;
                        let a = parse_inet_addr(af, b)?;
                        addrs.push(a);
                        let l = roundup(b[0] as usize);
                        if b.len() < l {
                            return Err(RouteError::MessageTooShort);
                        }
                        b = &b[l..];
                    }
                    _ => {
                        let (l, a) = default_fn(af, b)?;
                        addrs.push(a);
                        let ll = roundup(l as usize);
                        if b.len() < ll {
                            b = &b[l as usize..];
                        } else {
                            b = &b[ll..];
                        }
                    }
                }
            } else {
                let a = parse_default_addr(b)?;
                addrs.push(a);
                let l = roundup(b[0] as usize);
                if b.len() < l {
                    return Err(RouteError::MessageTooShort);
                }
                b = &b[l..];
            }
        }
        // The only remaining bytes in b should be alignment.
        // However, under some circumstances DragonFly BSD appears to put
        // more addresses in the message than are indicated in the address
        // bitmask, so don't check for this.
        Ok(addrs)
    }

    /// Parses `b` as an internet address for IPv4 or IPv6.
    fn parse_inet_addr(af: i32, b: &[u8]) -> Result<Addr, RouteError> {
        match af {
            libc::AF_INET => {
                if b.len() < sizeofSockaddrInet {
                    return Err(RouteError::InvalidAddress);
                }

                let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
                Ok(Addr::Inet4 { ip })
            }
            libc::AF_INET6 => {
                if b.len() < sizeofSockaddrInet6 {
                    return Err(RouteError::InvalidAddress);
                }

                let mut zone = u32::from_ne_bytes(b[24..28].try_into().unwrap());
                let mut oc: [u8; 16] = b[8..24].try_into().unwrap();
                if oc[0] == 0xfe && oc[1] & 0xc0 == 0x80
                    || oc[0] == 0xff && (oc[1] & 0x0f == 0x01 || oc[1] & 0x0f == 0x02)
                {
                    // KAME based IPv6 protocol stack usually
                    // embeds the interface index in the
                    // interface-local or link-local address as
                    // the kernel-internal form.
                    let id = u16::from_be_bytes(oc[2..4].try_into().unwrap()) as u32;
                    if id != 0 {
                        zone = id;
                        oc[2] = 0;
                        oc[3] = 0;
                    }
                }
                Ok(Addr::Inet6 {
                    ip: Ipv6Addr::from(oc),
                    zone,
                })
            }
            _ => Err(RouteError::InvalidAddress),
        }
    }

    /// Parses b as an internet address in conventional BSD kernel form.
    fn parse_kernel_inet_addr(af: i32, b: &[u8]) -> Result<(i32, Addr), RouteError> {
        // The encoding looks similar to the NLRI encoding.
        // +----------------------------+
        // | Length           (1 octet) |
        // +----------------------------+
        // | Address prefix  (variable) |
        // +----------------------------+
        //
        // The differences between the kernel form and the NLRI
        // encoding are:
        //
        // - The length field of the kernel form indicates the prefix
        //   length in bytes, not in bits
        //
        // - In the kernel form, zero value of the length field
        //   doesn't mean 0.0.0.0/0 or ::/0
        //
        // - The kernel form appends leading bytes to the prefix field
        //   to make the <length, prefix> tuple to be conformed with
        //   the routing message boundary
        let mut l = b[0] as usize;

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            // On Darwin, an address in the kernel form is also used as a message filler.
            if l == 0 || b.len() > roundup(l) {
                l = roundup(l)
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            l = roundup(l);
        }

        if b.len() < l {
            return Err(RouteError::InvalidAddress);
        }
        // Don't reorder case expressions.
        // The case expressions for IPv6 must come first.
        const off4: usize = 4; // offset of in_addr
        const off6: usize = 8; // offset of in6_addr

        let addr = if b[0] as usize == sizeofSockaddrInet6 {
            let octets: [u8; 16] = b[off6..off6 + 16].try_into().unwrap();
            let ip = Ipv6Addr::from(octets);
            Addr::Inet6 { ip, zone: 0 }
        } else if af == libc::AF_INET6 {
            let mut octets = [0u8; 16];
            if l - 1 < off6 {
                octets[..l - 1].copy_from_slice(&b[1..l]);
            } else {
                octets.copy_from_slice(&b[l - off6..l]);
            }
            let ip = Ipv6Addr::from(octets);
            Addr::Inet6 { ip, zone: 0 }
        } else if b[0] as usize == sizeofSockaddrInet {
            let octets: [u8; 4] = b[off4..off4 + 4].try_into().unwrap();
            let ip = Ipv4Addr::from(octets);
            Addr::Inet4 { ip }
        } else {
            // an old fashion, AF_UNSPEC or unknown means AF_INET
            let mut octets = [0u8; 4];
            if l - 1 < off4 {
                octets[..l - 1].copy_from_slice(&b[1..l]);
            } else {
                octets.copy_from_slice(&b[l - off4..l]);
            }
            let ip = Ipv4Addr::from(octets);
            Addr::Inet4 { ip }
        };

        Ok((b[0] as _, addr))
    }

    fn parse_link_addr(b: &[u8]) -> Result<Addr, RouteError> {
        if b.len() < 8 {
            return Err(RouteError::InvalidAddress);
        }
        let (_, mut a) = parse_kernel_link_addr(libc::AF_LINK, &b[4..])?;

        if let Addr::Link { index, .. } = &mut a {
            *index = u16::from_ne_bytes(b[2..4].try_into().unwrap()) as _;
        }

        Ok(a)
    }

    // Parses b as a link-layer address in conventional BSD kernel form.
    fn parse_kernel_link_addr(_: i32, b: &[u8]) -> Result<(usize, Addr), RouteError> {
        // The encoding looks like the following:
        // +----------------------------+
        // | Type             (1 octet) |
        // +----------------------------+
        // | Name length      (1 octet) |
        // +----------------------------+
        // | Address length   (1 octet) |
        // +----------------------------+
        // | Selector length  (1 octet) |
        // +----------------------------+
        // | Data            (variable) |
        // +----------------------------+
        //
        // On some platforms, all-bit-one of length field means "don't
        // care".
        let mut nlen = b[1] as usize;
        let mut alen = b[2] as usize;
        let mut slen = b[3] as usize;

        if nlen == 0xff {
            nlen = 0;
        }
        if alen == 0xff {
            alen = 0;
        }
        if slen == 0xff {
            slen = 0;
        }

        let l = 4 + nlen + alen + slen;
        if b.len() < l {
            return Err(RouteError::InvalidAddress);
        }
        let mut data = &b[4..];

        let name = if nlen > 0 {
            let name = std::str::from_utf8(&data[..nlen])
                .map_err(|_| RouteError::InvalidAddress)?
                .to_string();
            data = &data[nlen..];
            Some(name)
        } else {
            None
        };

        let addr = if alen > 0 {
            Some(data[..alen].to_vec().into_boxed_slice())
        } else {
            None
        };

        let a = Addr::Link {
            index: 0,
            name,
            addr,
        };

        Ok((l, a))
    }

    fn parse_default_addr(b: &[u8]) -> Result<Addr, RouteError> {
        if b.len() < 2 || b.len() < b[0] as usize {
            return Err(RouteError::InvalidAddress);
        }
        Ok(Addr::Default {
            af: b[1] as _,
            raw: b[..b[0] as usize].to_vec().into_boxed_slice(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_fetch_parse_routing_table() {
            let rib_raw = fetch_routing_table().unwrap();
            assert!(!rib_raw.is_empty());
            println!("got rib: {}", rib_raw.len());
            let rib_parsed = parse_routing_table(&rib_raw).unwrap();
            println!("got {} entries", rib_parsed.len());
            assert!(!rib_parsed.is_empty());
        }

        struct ParseAddrsTest {
            attrs: i32,
            parse_fn: Box<dyn Fn(i32, &[u8]) -> Result<(i32, Addr), RouteError>>,
            b: Vec<u8>,
            addrs: Vec<Addr>,
        }

        #[test]
        #[cfg(target_endian = "little")]
        fn test_parse_addrs() {
            let parse_addrs_little_endian_tests = [
                ParseAddrsTest {
                    attrs: libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK | libc::RTA_BRD,
                    parse_fn: Box::new(parse_kernel_inet_addr),
                    b: vec![
                        0x38, 0x12, 0x0, 0x0, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x38, 0x12,
                        0x2, 0x0, 0x6, 0x3, 0x6, 0x0, 0x65, 0x6d, 0x31, 0x0, 0xc, 0x29, 0x66, 0x2c,
                        0xdc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x2, 0x0, 0x0,
                        0xac, 0x10, 0xdc, 0xb4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x2,
                        0x0, 0x0, 0xac, 0x10, 0xdc, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    ],
                    addrs: vec![
                        Addr::Link {
                            index: 0,
                            name: None,
                            addr: None,
                        },
                        Addr::Link {
                            index: 2,
                            name: Some("em1".to_string()),
                            addr: Some(vec![0x00, 0x0c, 0x29, 0x66, 0x2c, 0xdc].into_boxed_slice()),
                        },
                        Addr::Inet4 {
                            ip: Ipv4Addr::from([172, 16, 220, 180]),
                        },
                        /*nil,
                        nil,
                        nil,
                        nil,*/
                        Addr::Inet4 {
                            ip: Ipv4Addr::from([172, 16, 220, 255]),
                        },
                    ],
                },
                ParseAddrsTest {
                    attrs: libc::RTA_NETMASK | libc::RTA_IFP | libc::RTA_IFA,
                    parse_fn: Box::new(parse_kernel_inet_addr),
                    b: vec![
                        0x7, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0x0, 0x18, 0x12, 0xa, 0x0, 0x87, 0x8,
                        0x0, 0x0, 0x76, 0x6c, 0x61, 0x6e, 0x35, 0x36, 0x38, 0x32, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x2, 0x0, 0x0, 0xa9, 0xfe, 0x0, 0x1, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    ],
                    addrs: vec![
                        // nil,
                        // nil,
                        Addr::Inet4 {
                            ip: Ipv4Addr::from([255, 255, 255, 0]),
                        },
                        // nil,
                        Addr::Link {
                            index: 10,
                            name: Some("vlan5682".to_string()),
                            addr: None,
                        },
                        Addr::Inet4 {
                            ip: Ipv4Addr::from([169, 254, 0, 1]),
                        },
                        // nil,
                        // nil,
                    ],
                },
            ];

            for (i, tt) in parse_addrs_little_endian_tests.into_iter().enumerate() {
                let addrs = parse_addrs(tt.attrs, tt.parse_fn, &tt.b)
                    .unwrap_or_else(|_| panic!("failed {}", i));

                assert_eq!(addrs, tt.addrs, "{}", i);
            }
        }
    }
}
