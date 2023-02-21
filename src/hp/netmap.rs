//! Based on tailscale/types/netmap

use super::cfg;

#[derive(Debug)]
pub struct NetworkMap {
    pub peers: Vec<cfg::Node>,
}
