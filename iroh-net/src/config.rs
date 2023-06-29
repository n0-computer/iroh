//! Configuration types.

use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use serde::{Deserialize, Serialize};

use super::key;

/// Fake WireGuard endpoint IP address that means to
/// use DERP. When used (in the Node.DERP field), the port number of
/// the WireGuard endpoint is the DERP region ID number to use.
///
/// Mnemonic: 3.3.40 are numbers above the keys D, E, R, P.
pub const DERP_MAGIC_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 3, 3, 40));

/// An endpoint IPPort and an associated type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// The address of the endpoint.
    pub addr: SocketAddr,
    /// The kind of endpoint.
    pub typ: EndpointType,
}

/// Type of endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    /// Whether ICMPv4 works. Empty means not checked.
    pub working_icm_pv4: Option<bool>,

    /// Whether we have an existing portmap open (UPnP, PMP, or PCP).
    pub have_port_map: bool,

    /// Probe indicating the presence of port mapping protocols on the LAN.
    pub portmap_probe: Option<portmapper::ProbeOutput>,

    /// This node's preferred DERP server for incoming traffic. The node might be be temporarily
    /// connected to multiple DERP servers (to send to other nodes)
    /// but PreferredDERP is the instance number that the node
    /// subscribes to traffic at. Zero means disconnected or unknown.
    pub preferred_derp: u16,

    /// LinkType is the current link type, if known.
    pub link_type: Option<LinkType>,

    /// The fastest recent time to reach various DERP STUN servers, in seconds. The map key is the
    /// "regionID-v4" or "-v6"; it was previously the DERP server's STUN host:port.
    ///
    /// This should only be updated rarely, or when there's a
    /// material change, as any change here also gets uploaded to the control plane.
    pub derp_latency: HashMap<String, f64>,
}

impl NetInfo {
    /// reports whether `self` and `other` are basically equal, ignoring changes in DERP ServerLatency & RegionLatency.
    pub fn basically_equal(&self, other: &Self) -> bool {
        self.mapping_varies_by_dest_ip == other.mapping_varies_by_dest_ip
            && self.hair_pinning == other.hair_pinning
            && self.working_ipv6 == other.working_ipv6
            && self.os_has_ipv6 == other.os_has_ipv6
            && self.working_udp == other.working_udp
            && self.working_icm_pv4 == other.working_icm_pv4
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

/// Contains response information for the "tailscale ping" subcommand,
/// saying how Tailscale can reach a Tailscale IP or subnet-routed IP.
/// See tailcfg.PingResponse for a related response that is sent back to control
/// for remote diagnostic pings.
// Based on tailscale/ipnstate
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PingResult {
    /// ping destination
    pub ip: Option<IpAddr>,
    /// Tailscale IP of node handling IP (different for subnet routers)
    pub node_ip: Option<IpAddr>,
    /// DNS name base or (possibly not unique) hostname
    pub node_name: Option<String>,
    /// Perceived latency in seconds.
    pub latency_seconds: Option<f64>,
    /// The ip:port if direct UDP was used. It is not currently set for TSMP pings.
    pub endpoint: Option<SocketAddr>,
    /// Non-zero DERP region ID if DERP was used. It is not currently set for TSMP pings.
    pub derp_region_id: Option<u16>,
    /// The three-letter region code corresponding to derp_region_id. It is not currently set for TSMP pings.
    pub derp_region_code: Option<String>,
    /// Whether the ping request error is due to it being a ping to the local node.
    pub is_local_ip: Option<bool>,

    /// Did any error occur?
    pub err: Option<String>,
}

/// A node or peer in the iroh network.
///
/// Nodes are primarily identified by their [`Node::key`].
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    /// The public key or PeerID, the primary identifier of this node.
    pub key: key::node::PublicKey,
    /// DNS name of the peer.
    pub name: Option<String>,
    /// Direct IP addresses of this Node.
    ///
    /// These are the IP addresses this node is listening on.
    pub addresses: Vec<IpAddr>,
    /// Endpoints on which we think the node is reachable.
    ///
    /// These are populated from STUN results as well as local LAN addresses.
    pub endpoints: Vec<SocketAddr>,
    /// DERP-in-IP:port ("127.3.3.40:N") endpoint. Only stores the `N`.
    ///
    /// If this nodes expected to be reachable via DERP relaying.
    pub derp: Option<u16>,
}
