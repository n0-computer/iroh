//! Configuration types.

use std::{collections::BTreeMap, fmt::Display, net::SocketAddr};

use crate::relay::RelayUrl;

use super::portmapper;

/// A *direct address* on which an iroh-node might be contactable.
///
/// Direct addresses are UDP socket addresses on which an iroh-net node could potentially be
/// contacted.  These can come from various sources depending on the network topology of the
/// iroh-net node, see [`DirectAddressType`] for the several kinds of sources.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirectAddress {
    /// The address.
    pub addr: SocketAddr,
    /// The origin of this direct address.
    pub typ: DirectAddressType,
}

/// The type of direct address.
///
/// These are the various sources or origins from which an iroh-net node might have found a
/// possible [`DirectAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DirectAddressType {
    /// Not yet determined..
    Unknown,
    /// A locally bound socket address.
    Local,
    /// Public internet address discovered via STUN.
    ///
    /// When possible an iroh-net node will perform STUN to discover which is the address
    /// from which it sends data on the public internet.  This can be different from locally
    /// bound addresses when the node is on a local network wich performs NAT or similar.
    Stun,
    /// An address assigned by the router using port mapping.
    ///
    /// When possible an iroh-net node will request a port mapping from the local router to
    /// get a publicly routable direct address.
    Portmapped,
    /// Hard NAT: STUN'ed IPv4 address + local fixed port.
    ///
    /// It is possible to configure iroh-net to bound to a specific port and independently
    /// configure the router to forward this port to the iroh-net node.  This indicates a
    /// situation like this, which still uses STUN to discover the public address.
    Stun4LocalPort,
}

impl Display for DirectAddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectAddressType::Unknown => write!(f, "?"),
            DirectAddressType::Local => write!(f, "local"),
            DirectAddressType::Stun => write!(f, "stun"),
            DirectAddressType::Portmapped => write!(f, "portmap"),
            DirectAddressType::Stun4LocalPort => write!(f, "stun4localport"),
        }
    }
}

/// Contains information about the host's network state.
#[derive(Debug, Clone, PartialEq)]
pub struct NetInfo {
    /// Says whether the host's NAT mappings vary based on the destination IP.
    pub mapping_varies_by_dest_ip: Option<bool>,

    /// If their router does hairpinning. It reports true even if there's no NAT involved.
    pub hair_pinning: Option<bool>,

    /// Whether the host has IPv6 internet connectivity.
    pub working_ipv6: Option<bool>,

    /// Whether the OS supports IPv6 at all, regardless of whether IPv6 internet connectivity is available.
    pub os_has_ipv6: Option<bool>,

    /// Whether the host has UDP internet connectivity.
    pub working_udp: Option<bool>,

    /// Whether ICMPv4 works, `None` means not checked.
    pub working_icmp_v4: Option<bool>,

    /// Whether ICMPv6 works, `None` means not checked.
    pub working_icmp_v6: Option<bool>,

    /// Whether we have an existing portmap open (UPnP, PMP, or PCP).
    pub have_port_map: bool,

    /// Probe indicating the presence of port mapping protocols on the LAN.
    pub portmap_probe: Option<portmapper::ProbeOutput>,

    /// This node's preferred relay server for incoming traffic. The node might be be temporarily
    /// connected to multiple relay servers (to send to other nodes)
    /// but PreferredRelay is the instance number that the node
    /// subscribes to traffic at. Zero means disconnected or unknown.
    pub preferred_relay: Option<RelayUrl>,

    /// LinkType is the current link type, if known.
    pub link_type: Option<LinkType>,

    /// The fastest recent time to reach various relay STUN servers, in seconds.
    ///
    /// This should only be updated rarely, or when there's a
    /// material change, as any change here also gets uploaded to the control plane.
    pub relay_latency: BTreeMap<String, f64>,
}

impl NetInfo {
    /// reports whether `self` and `other` are basically equal, ignoring changes in relay ServerLatency & RelayLatency.
    pub fn basically_equal(&self, other: &Self) -> bool {
        let eq_icmp_v4 = match (self.working_icmp_v4, other.working_icmp_v4) {
            (Some(slf), Some(other)) => slf == other,
            _ => true, // ignore for comparison if only one report had this info
        };
        let eq_icmp_v6 = match (self.working_icmp_v6, other.working_icmp_v6) {
            (Some(slf), Some(other)) => slf == other,
            _ => true, // ignore for comparison if only one report had this info
        };
        self.mapping_varies_by_dest_ip == other.mapping_varies_by_dest_ip
            && self.hair_pinning == other.hair_pinning
            && self.working_ipv6 == other.working_ipv6
            && self.os_has_ipv6 == other.os_has_ipv6
            && self.working_udp == other.working_udp
            && eq_icmp_v4
            && eq_icmp_v6
            && self.have_port_map == other.have_port_map
            && self.portmap_probe == other.portmap_probe
            && self.preferred_relay == other.preferred_relay
            && self.link_type == other.link_type
    }
}

/// The type of link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// A wired link (ethernet, fiber, etc).
    Wired,
    /// A WiFi link.
    Wifi,
    /// LTE, 4G, 3G, etc.
    Mobile,
}
