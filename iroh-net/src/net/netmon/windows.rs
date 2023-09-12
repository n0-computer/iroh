use anyhow::Result;
use tokio::{io::AsyncReadExt, sync::mpsc, task::JoinHandle};

#[derive(Debug)]
pub struct Message;

#[derive(Debug)]
pub struct RouteMonitor {
    handle: JoinHandle<()>,
}

impl Drop for RouteMonitor {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl RouteMonitor {
    pub async fn new(sender: mpsc::Sender<Message>) -> Result<Self> {
        todo!()
    }
}

pub(super) fn is_interesting_interface(name: &str) -> bool {
    todo!()
}
