//! Based on  <https://cs.opensource.google/go/x/net/+/master:route>

#![allow(unused)]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use once_cell::sync::Lazy;
use tracing::warn;

use super::DefaultRouteDetails;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use macos::*;

pub async fn default_route() -> Option<DefaultRouteDetails> {
    let idx = default_route_interface_index()?;
    let interfaces = default_net::get_interfaces();
    let iface = interfaces.into_iter().find(|i| i.index == idx)?;

    Some(DefaultRouteDetails {
        interface_index: idx,
        interface_name: iface.name,
        interface_description: None,
    })
}

pub fn likely_home_router() -> Option<IpAddr> {
    let rib = fetch_routing_table()?;
    let msgs = parse_routing_table(&rib)?;
    for rm in msgs {
        if !is_default_gateway(&rm) {
            continue;
        }

        if let Some(gw) = rm.addrs.get(libc::RTAX_GATEWAY as usize) {
            if let Addr::Inet4 { ip } = gw {
                return Some(IpAddr::V4(*ip));
            }

            if let Addr::Inet6 { ip, .. } = gw {
                return Some(IpAddr::V6(*ip));
            }
        }
    }
    None
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
    match fetch_rib(libc::AF_UNSPEC, libc::NET_RT_DUMP, 0) {
        Ok(res) => Some(res),
        Err(err) => {
            warn!("fetch_rib failed: {:?}", err);
            None
        }
    }
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd",))]
fn parse_routing_table(rib: &[u8]) -> Option<Vec<RouteMessage>> {
    match parse_rib(libc::NET_RT_IFLIST, rib) {
        Ok(res) => Some(res),
        Err(err) => {
            warn!("parse_rib failed: {:?}", err);
            None
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios",))]
fn fetch_routing_table() -> Option<Vec<u8>> {
    const NET_RT_DUMP2: i32 = 7;
    match fetch_rib(libc::AF_UNSPEC, NET_RT_DUMP2, 0) {
        Ok(res) => Some(res),
        Err(err) => {
            warn!("fetch_rib failed: {:?}", err);
            None
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios",))]
fn parse_routing_table(rib: &[u8]) -> Option<Vec<RouteMessage>> {
    match parse_rib(libc::NET_RT_IFLIST2, rib) {
        Ok(res) => {
            let res = res
                .into_iter()
                .filter_map(|m| match m {
                    WireMessage::Route(r) => Some(r),
                    _ => None,
                })
                .collect();
            Some(res)
        }
        Err(err) => {
            warn!("parse_rib failed: {:?}", err);
            None
        }
    }
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

#[derive(Debug)]
pub enum WireMessage {
    Route(RouteMessage),
    Interface(InterfaceMessage),
    InterfaceAddr(InterfaceAddrMessage),
    InterfaceMulticastAddr(InterfaceMulticastAddrMessage),
}

impl WireFormat {
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "macos",
        target_os = "ios"
    ))]
    fn parse(&self, _typ: RIBType, data: &[u8]) -> Result<Option<WireMessage>, RouteError> {
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

                Ok(Some(WireMessage::Route(m)))
            }
            MessageType::Interface => {
                if data.len() < self.body_off {
                    return Err(RouteError::MessageTooShort);
                }
                let l = u16::from_ne_bytes(data[..2].try_into().unwrap());
                if data.len() < l as usize {
                    return Err(RouteError::InvalidMessage);
                }

                let attrs = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                if attrs as libc::c_int & libc::RTA_IFP == 0 {
                    return Ok(None);
                }
                let addr = parse_link_addr(&data[self.body_off..])?;
                let name = addr.name().map(|s| s.to_string());
                let m = InterfaceMessage {
                    version: data[2] as _,
                    r#type: data[3] as _,
                    flags: u32::from_ne_bytes(data[8..12].try_into().unwrap()) as _,
                    index: u16::from_ne_bytes(data[12..14].try_into().unwrap()) as _,
                    ext_off: self.ext_off,
                    addr_rtax_ifp: addr,
                    name,
                };

                Ok(Some(WireMessage::Interface(m)))
            }
            MessageType::InterfaceAddr => {
                if data.len() < self.body_off {
                    return Err(RouteError::MessageTooShort);
                }
                let l = u16::from_ne_bytes(data[..2].try_into().unwrap());
                if data.len() < l as usize {
                    return Err(RouteError::InvalidMessage);
                }

                #[cfg(target_arch = "netbsd")]
                let index = u16::from_ne_bytes(data[16..18].try_into().unwrap());
                #[cfg(not(target_arch = "netbsd"))]
                let index = u16::from_ne_bytes(data[12..14].try_into().unwrap());

                let addrs = parse_addrs(
                    u32::from_ne_bytes(data[4..8].try_into().unwrap()) as _,
                    parse_kernel_inet_addr,
                    &data[self.body_off..],
                )?;

                let m = InterfaceAddrMessage {
                    version: data[2] as _,
                    r#type: data[3] as _,
                    flags: u32::from_ne_bytes(data[8..12].try_into().unwrap()) as _,
                    index: index as _,
                    addrs,
                };
                Ok(Some(WireMessage::InterfaceAddr(m)))
            }
            MessageType::InterfaceMulticastAddr => {
                if data.len() < self.body_off {
                    return Err(RouteError::MessageTooShort);
                }
                let l = u16::from_ne_bytes(data[..2].try_into().unwrap());
                if data.len() < l as usize {
                    return Err(RouteError::InvalidMessage);
                }
                let addrs = parse_addrs(
                    u32::from_ne_bytes(data[4..8].try_into().unwrap()) as _,
                    parse_kernel_inet_addr,
                    &data[self.body_off..],
                )?;
                let m = InterfaceMulticastAddrMessage {
                    version: data[2] as _,
                    r#type: data[3] as _,
                    flags: u32::from_ne_bytes(data[8..12].try_into().unwrap()) as _,
                    index: u16::from_ne_bytes(data[12..14].try_into().unwrap()) as _,
                    addrs,
                };
                Ok(Some(WireMessage::InterfaceMulticastAddr(m)))
            }
        }
    }

    #[cfg(target_os = "openbsd")]
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

static ROUTING_STACK: Lazy<RoutingStack> = Lazy::new(probe_routing_stack);

struct RoutingStack {
    rtm_version: i32,
    kernel_align: usize,
    wire_formats: HashMap<i32, WireFormat>,
}

/// Parses b as a routing information base and returns a list of routing messages.
pub fn parse_rib(typ: RIBType, data: &[u8]) -> Result<Vec<WireMessage>, RouteError> {
    if !is_valid_rib_type(typ) {
        return Err(RouteError::InvalidRibType(typ));
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
///  Version       = <must be specified>
///  Type          = <must be specified>
///  Flags         = <must be specified>
///  Index         = <must be specified if necessary>
///  ID            = <must be specified>
///  Seq           = <must be specified>
///  Addrs         = <must be specified>
#[derive(Debug)]
pub struct RouteMessage {
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

/// An interface message.
#[derive(Debug)]
pub struct InterfaceMessage {
    /// Message version
    pub version: isize,
    /// Message type
    pub r#type: isize,
    // Interface flags
    pub flags: isize,
    // interface index
    pub index: isize,
    /// Interface name
    pub name: Option<String>,
    /// Addresses
    pub addr_rtax_ifp: Addr,
    /// Offset of header extension
    pub ext_off: usize,
}

/// An interface address message.
#[derive(Debug)]
pub struct InterfaceAddrMessage {
    /// Message version
    pub version: isize,
    /// Message type
    pub r#type: isize,
    /// Interface flags
    pub flags: isize,
    /// Interface index
    pub index: isize,
    /// Addresses
    pub addrs: Vec<Addr>,
}

/// Interface multicast address message.
#[derive(Debug)]
pub struct InterfaceMulticastAddrMessage {
    /// message version
    pub version: isize,
    /// message type
    pub r#type: isize,
    /// interface flags
    pub flags: isize,
    /// interface index
    pub index: isize,
    /// addresses
    pub addrs: Vec<Addr>,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod macos {
    use super::*;

    // Hardcoded based on the generated values here: https://cs.opensource.google/go/x/net/+/master:route/zsys_darwin.go

    pub(super) const SIZEOF_IF_MSGHDR_DARWIN15: usize = 0x70;
    pub(super) const SIZEOF_IFA_MSGHDR_DARWIN15: usize = 0x14;
    pub(super) const SIZEOF_IFMA_MSGHDR_DARWIN15: usize = 0x10;
    pub(super) const SIZEOF_IF_MSGHDR2_DARWIN15: usize = 0xa0;
    pub(super) const SIZEOF_IFMA_MSGHDR2_DARWIN15: usize = 0x14;
    pub(super) const SIZEOF_IF_DATA_DARWIN15: usize = 0x60;
    pub(super) const SIZEOF_IF_DATA64_DARWIN15: usize = 0x80;

    pub(super) const SIZEOF_RT_MSGHDR_DARWIN15: usize = 0x5c;
    pub(super) const SIZEOF_RT_MSGHDR2_DARWIN15: usize = 0x5c;
    pub(super) const SIZEOF_RT_METRICS_DARWIN15: usize = 0x38;

    pub(super) const SIZEOF_SOCKADDR_STORAGE: usize = 0x80;
    pub(super) const SIZEOF_SOCKADDR_INET: usize = 0x10;
    pub(super) const SIZEOF_SOCKADDR_INET6: usize = 0x1c;

    pub(super) fn probe_routing_stack() -> RoutingStack {
        let rtm_version = libc::RTM_VERSION;

        let rtm = WireFormat {
            ext_off: 36,
            body_off: SIZEOF_RT_MSGHDR_DARWIN15,
            typ: MessageType::Route,
        };
        let rtm2 = WireFormat {
            ext_off: 36,
            body_off: SIZEOF_RT_MSGHDR2_DARWIN15,
            typ: MessageType::Route,
        };
        let ifm = WireFormat {
            ext_off: 16,
            body_off: SIZEOF_IF_MSGHDR_DARWIN15,
            typ: MessageType::Interface,
        };
        let ifm2 = WireFormat {
            ext_off: 32,
            body_off: SIZEOF_IF_MSGHDR2_DARWIN15,
            typ: MessageType::Interface,
        };
        let ifam = WireFormat {
            ext_off: SIZEOF_IFA_MSGHDR_DARWIN15,
            body_off: SIZEOF_IFA_MSGHDR_DARWIN15,
            typ: MessageType::InterfaceAddr,
        };
        let ifmam = WireFormat {
            ext_off: SIZEOF_IFMA_MSGHDR_DARWIN15,
            body_off: SIZEOF_IFMA_MSGHDR_DARWIN15,
            typ: MessageType::InterfaceMulticastAddr,
        };
        let ifmam2 = WireFormat {
            ext_off: SIZEOF_IFMA_MSGHDR2_DARWIN15,
            body_off: SIZEOF_IFMA_MSGHDR2_DARWIN15,
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
}

/// Represents a type of routing information base.
type RIBType = i32;

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("message mismatch")]
    MessageMismatch,
    #[error("message too short")]
    MessageTooShort,
    #[error("invalid message")]
    InvalidMessage,
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid rib type: {0}")]
    InvalidRibType(RIBType),
    #[error("io error calling: '{0}': {1:?}")]
    Io(&'static str, std::io::Error),
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
            return Err(RouteError::Io("sysctl", std::io::Error::last_os_error()));
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
            let io_err = std::io::Error::last_os_error();
            const MAX_TRIES: usize = 3;
            if io_err.raw_os_error().unwrap_or_default() == libc::ENOMEM && round < MAX_TRIES {
                continue;
            }
            return Err(RouteError::Io("sysctl", io_err));
        }
        return Ok(b);
    }
}

/// Represents an address associated with packet routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
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

    pub fn name(&self) -> Option<&str> {
        match self {
            Addr::Link { name, .. } => name.as_ref().map(|s| s.as_str()),
            _ => None,
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
            if b.len() < SIZEOF_SOCKADDR_INET {
                return Err(RouteError::InvalidAddress);
            }

            let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            Ok(Addr::Inet4 { ip })
        }
        libc::AF_INET6 => {
            if b.len() < SIZEOF_SOCKADDR_INET6 {
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
    const OFF4: usize = 4; // offset of in_addr
    const OFF6: usize = 8; // offset of in6_addr

    let addr = if b[0] as usize == SIZEOF_SOCKADDR_INET6 {
        let octets: [u8; 16] = b[OFF6..OFF6 + 16].try_into().unwrap();
        let ip = Ipv6Addr::from(octets);
        Addr::Inet6 { ip, zone: 0 }
    } else if af == libc::AF_INET6 {
        let mut octets = [0u8; 16];
        if l - 1 < OFF6 {
            octets[..l - 1].copy_from_slice(&b[1..l]);
        } else {
            octets.copy_from_slice(&b[l - OFF6..l]);
        }
        let ip = Ipv6Addr::from(octets);
        Addr::Inet6 { ip, zone: 0 }
    } else if b[0] as usize == SIZEOF_SOCKADDR_INET {
        let octets: [u8; 4] = b[OFF4..OFF4 + 4].try_into().unwrap();
        let ip = Ipv4Addr::from(octets);
        Addr::Inet4 { ip }
    } else {
        // an old fashion, AF_UNSPEC or unknown means AF_INET
        let mut octets = [0u8; 4];
        if l - 1 < OFF4 {
            octets[..l - 1].copy_from_slice(&b[1..l]);
        } else {
            octets.copy_from_slice(&b[l - OFF4..l]);
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
        #[allow(clippy::type_complexity)]
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
                    0x38, 0x12, 0x0, 0x0, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x38, 0x12, 0x2, 0x0, 0x6, 0x3,
                    0x6, 0x0, 0x65, 0x6d, 0x31, 0x0, 0xc, 0x29, 0x66, 0x2c, 0xdc, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x10, 0x2, 0x0, 0x0, 0xac, 0x10, 0xdc, 0xb4, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x2, 0x0, 0x0, 0xac, 0x10, 0xdc, 0xff, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
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
                    0x0, 0x0, 0x76, 0x6c, 0x61, 0x6e, 0x35, 0x36, 0x38, 0x32, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x10, 0x2, 0x0, 0x0, 0xa9, 0xfe, 0x0, 0x1, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0,
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
