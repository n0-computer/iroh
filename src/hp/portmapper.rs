use anyhow::Error;

#[derive(Debug, Clone)]
pub struct PortMapper {}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub pcp: bool,
    pub pmp: bool,
    pub upnp: bool,
}

/// A port mapping client.
#[derive(Debug, Clone)]
pub struct Client {}

impl Client {
    pub fn new() -> Self {
        todo!()
    }

    pub async fn probe(&self) -> Result<ProbeResult, Error> {
        todo!()
    }

    /// Updates the local port number to which we want to port map UDP traffic.
    pub async fn set_local_port(&self, local_port: u16) {
        todo!()
    }
}
