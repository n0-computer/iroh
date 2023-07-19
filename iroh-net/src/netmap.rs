//! Based on tailscale/types/netmap

use super::config;

/// The local view of the iroh network.
///
/// This contains all the peers the local node knows about.
#[derive(Clone, Debug)]
pub struct NetworkMap {
    /// Known peers in the network.
    pub peers: Vec<config::Node>,
}
