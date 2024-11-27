use anyhow::Result;
use tokio::sync::mpsc;

use super::actor::NetworkMessage;

#[derive(Debug)]
pub(super) struct RouteMonitor {
    _sender: mpsc::Sender<NetworkMessage>,
}

impl RouteMonitor {
    pub(super) fn new(_sender: mpsc::Sender<NetworkMessage>) -> Result<Self> {
        // Very sad monitor. Android doesn't allow us to do this

        Ok(RouteMonitor { _sender })
    }
}

pub(super) fn is_interesting_interface(_name: &str) -> bool {
    true
}
