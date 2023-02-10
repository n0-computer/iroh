use anyhow::Error;

#[derive(Debug, Clone)]
pub struct PortMapper {}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub pcp: bool,
    pub pmp: bool,
    pub upnp: bool,
}

impl PortMapper {
    pub async fn probe(&self) -> Result<ProbeResult, Error> {
        todo!()
    }
}
