use anyhow::Result;

#[derive(Debug)]
pub struct Message;

#[derive(Debug)]
pub struct RouteMonitor {}

impl RouteMonitor {
    pub async fn new(_sender: flume::Sender<Message>) -> Result<Self> {
        // Very sad monitor. Android doesn't allow us to do this

        Ok(RouteMonitor {})
    }
}

pub(super) fn is_interesting_interface(_name: &str) -> bool {
    true
}
