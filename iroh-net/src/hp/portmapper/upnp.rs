use std::{
    fmt::Display,
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    time::{Duration, Instant},
};

use anyhow::Result;
use igd::aio as aigd;

use iroh_metrics::{inc, portmap::PortmapMetrics as Metrics};
use tracing::debug;

pub use aigd::Gateway;

/// Seconds we ask the router to maintain the port mapping. 0 means infinite.
const PORT_MAPPING_LEASE_DURATION_SECONDS: u32 = 0;

/// Maximum duration a UPnP search can take before timing out.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(1);

const PORT_MAPPING_DESCRIPTION: &str = "iroh-portmap";

#[derive(derive_more::Debug, Clone)]
pub struct Mapping {
    /// The internet Gateway device (router) used to create this mapping.
    #[debug("{}", gateway)]
    gateway: aigd::Gateway,
    /// The external address obtained by this mapping.
    external_addr: SocketAddrV4,
    /// Local address used to create this mapping.
    local_addr: SocketAddrV4,
}

impl Mapping {
    pub(crate) async fn new(local_addr: Ipv4Addr, port: NonZeroU16) -> Result<Self> {
        let local_addr = SocketAddrV4::new(local_addr, port.into());
        let gateway = aigd::search_gateway(igd::SearchOptions {
            timeout: Some(SEARCH_TIMEOUT),
            ..Default::default()
        })
        .await?;

        let external_addr = gateway
            .get_any_address(
                igd::PortMappingProtocol::UDP,
                local_addr,
                PORT_MAPPING_LEASE_DURATION_SECONDS,
                PORT_MAPPING_DESCRIPTION,
            )
            .await?;
        Ok(Mapping {
            gateway,
            external_addr,
            local_addr,
        })
    }

    pub fn half_lifetime(&self) -> Duration {
        // TODO(@divma): docs
        Duration::from_secs(60 * 60)
    }

    /// Releases the mapping.
    pub(crate) async fn release(self) -> Result<()> {
        let Mapping {
            gateway,
            external_addr,
            ..
        } = self;
        gateway
            .remove_port(igd::PortMappingProtocol::UDP, external_addr.port())
            .await?;
        Ok(())
    }

    /// Renews the mapping and updates the external address (external ip could change).
    pub(crate) async fn renew(&mut self) -> Result<()> {
        self.gateway
            .add_port(
                igd::PortMappingProtocol::UDP,
                self.external_addr.port(),
                self.local_addr,
                PORT_MAPPING_LEASE_DURATION_SECONDS,
                PORT_MAPPING_DESCRIPTION,
            )
            .await?;
        let external_ip = self.gateway.get_external_ip().await?;
        self.external_addr.set_ip(external_ip);

        Ok(())
    }

    // external indicates what port the mapping can be reached from on the outside.
    pub fn external(&self) -> SocketAddrV4 {
        self.external_addr
    }
}

/// Searchs for upnp gateways, returns the [`SocketAddrV4`] if any was found.
pub async fn probe_available() -> Option<Gateway> {
    inc!(Metrics::UpnpProbes);
    match aigd::search_gateway(igd::SearchOptions {
        timeout: Some(SEARCH_TIMEOUT),
        ..Default::default()
    })
    .await
    {
        Ok(gateway) => Some(gateway),
        Err(e) => {
            inc!(Metrics::UpnpProbesFailed);
            debug!("upnp probe failed: {e}");
            None
        }
    }
}

impl Display for Mapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UPnP mapping {} -> {}",
            self.local_addr, self.external_addr
        )
    }
}
