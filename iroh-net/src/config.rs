//! Configuration types.

use std::{collections::BTreeMap, fmt::Display, net::SocketAddr};

use crate::derp::DerpUrl;

use super::portmapper;

// TODO: This re-uses "Endpoint" again, a term that already means "a quic endpoint" and "a
// magicsock endpoint". this time it means "an IP address on which our local magicsock
// endpoint is listening".  Name this better.
/// An endpoint IPPort and an associated type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    /// The address of the endpoint.
    pub addr: SocketAddr,
    /// The kind of endpoint.
    pub typ: EndpointType,
}

/// Type of endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EndpointType {
    /// Endpoint kind has not been determined yet.
    Unknown,
    /// Endpoint is bound to a local address.
    Local,
    /// Endpoint has a publicly reachable address found via STUN.
    Stun,
    /// Endpoint uses a port mapping in the router.
    Portmapped,
    /// Hard NAT: STUN'ed IPv4 address + local fixed port.
    Stun4LocalPort,
}

impl Display for EndpointType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointType::Unknown => write!(f, "?"),
            EndpointType::Local => write!(f, "local"),
            EndpointType::Stun => write!(f, "stun"),
            EndpointType::Portmapped => write!(f, "portmap"),
            EndpointType::Stun4LocalPort => write!(f, "stun4localport"),
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

    /// Whether ICMPv4 works, empty means not checked.
    pub working_icmp_v4: Option<bool>,

    /// Whether ICMPv6 works, empty means not checked.
    pub working_icmp_v6: Option<bool>,

    /// Whether we have an existing portmap open (UPnP, PMP, or PCP).
    pub have_port_map: bool,

    /// Probe indicating the presence of port mapping protocols on the LAN.
    pub portmap_probe: Option<portmapper::ProbeOutput>,

    /// This node's preferred DERP server for incoming traffic. The node might be be temporarily
    /// connected to multiple DERP servers (to send to other nodes)
    /// but PreferredDERP is the instance number that the node
    /// subscribes to traffic at. Zero means disconnected or unknown.
    pub preferred_derp: Option<DerpUrl>,

    /// LinkType is the current link type, if known.
    pub link_type: Option<LinkType>,

    /// The fastest recent time to reach various DERP STUN servers, in seconds.
    ///
    /// This should only be updated rarely, or when there's a
    /// material change, as any change here also gets uploaded to the control plane.
    pub derp_latency: BTreeMap<String, f64>,
}

impl NetInfo {
    /// reports whether `self` and `other` are basically equal, ignoring changes in DERP ServerLatency & DerpLatency.
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
            && self.preferred_derp == other.preferred_derp
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
