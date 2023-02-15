//! Provides facilities for monitoring network
//! interface and route changes. It primarily exists to know when
//! portable devices move between different networks.
//!
//! Based on tailscale/wgengine/monitor

use super::interfaces;

/// Represents a monitoring instance.
#[derive(Debug)]
pub struct Monitor {}

impl Monitor {
    pub fn interface_state(&self) -> interfaces::State {
        todo!()
    }
}
