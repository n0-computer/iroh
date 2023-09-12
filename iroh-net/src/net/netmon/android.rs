use anyhow::Result;
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct Message;

#[derive(Debug)]
pub struct RouteMonitor {}

impl RouteMonitor {
    pub async fn new(_sender: mpsc::Sender<Message>) -> Result<Self> {
        // Very sad monitor. Android doesn't allow us to do this

        Ok(RouteMonitor {})
    }
}

pub(super) fn is_interesting_interface(name: &str) -> bool {
    true
}
