//! Types from tailscale/tailcfg

use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

/// Fake WireGuard endpoint IP address that means to
/// use DERP. When used (in the Node.DERP field), the port number of
/// the WireGuard endpoint is the DERP region ID number to use.
///
/// Mnemonic: 3.3.40 are numbers above the keys D, E, R, P.
pub const DERP_MAGIC_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 3, 3, 30));

/// An endpoint IPPort and an associated type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub typ: EndpointType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointType {
    Unknown,
    Local,
    Stun,
    Portmapped,
    /// hard NAT: STUN'ed IPv4 address + local fixed port
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

    /// Whether UPnP appears present on the LAN. Empty means not checked.
    pub upnp: Option<bool>,

    /// Whether NAT-PMP appears present on the LAN. Empty means not checked.
    pub pmp: Option<bool>,

    /// Whether PCP appears present on the LAN. Empty means not checked.
    pub pcp: Option<bool>,

    /// This node's preferred DERP server for incoming traffic. The node might be be temporarily
    /// connected to multiple DERP servers (to send to other nodes)
    /// but PreferredDERP is the instance number that the node
    /// subscribes to traffic at. Zero means disconnected or unknown.
    pub preferred_derp: usize,

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
    pub fn basically_equal(&self, other: &Self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Wired,
    Wifi,
    //LTE, 4G, 3G, etc
    Mobile,
}

/// Contains response information for the "tailscale ping" subcommand,
/// saying how Tailscale can reach a Tailscale IP or subnet-routed IP.
/// See tailcfg.PingResponse for a related response that is sent back to control
/// for remote diagnostic pings.
// Based on tailscale/ipnstate
#[derive(Debug, Clone, PartialEq)]
pub struct PingResult {
    /// ping destination
    pub ip: IpAddr,
    /// Tailscale IP of node handling IP (different for subnet routers)
    pub node_ip: IpAddr,
    /// DNS name base or (possibly not unique) hostname
    pub node_name: String,

    pub err: String,
    pub latency_seconds: f64,

    /// The ip:port if direct UDP was used. It is not currently set for TSMP pings.
    pub endpoint: SocketAddr,

    /// Non-zero DERP region ID if DERP was used. It is not currently set for TSMP pings.
    pub derp_region_id: usize,

    /// The three-letter region code corresponding to derp_region_id. It is not currently set for TSMP pings.
    pub derp_region_code: String,

    /// Whether the ping request error is due to it being a ping to the local node.
    pub is_local_ip: bool,
}
