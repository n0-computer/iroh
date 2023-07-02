use std::{
    fmt::Display,
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    time::Duration,
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
    external_ip: Ipv4Addr,
    /// External port obtained by this mapping.
    external_port: NonZeroU16,
    /// Local address used to create this mapping.
    local_addr: SocketAddrV4,
}

impl Mapping {
    pub(crate) async fn new(
        local_addr: Ipv4Addr,
        port: NonZeroU16,
        gateway: Option<aigd::Gateway>,
        preferred_port: Option<NonZeroU16>,
    ) -> Result<Self> {
        let local_addr = SocketAddrV4::new(local_addr, port.into());

        // search for a gateway if there is not one already
        let gateway = if let Some(known_gateway) = gateway {
            known_gateway
        } else {
            aigd::search_gateway(igd::SearchOptions {
                timeout: Some(SEARCH_TIMEOUT),
                ..Default::default()
            })
            .await?
        };

        let external_ip = gateway.get_external_ip().await?;

        // if we are trying to get a specific external port, try this first. If this fails, default
        // to try to get any port
        if let Some(external_port) = preferred_port {
            if gateway
                .add_port(
                    igd::PortMappingProtocol::UDP,
                    external_port.into(),
                    local_addr,
                    PORT_MAPPING_LEASE_DURATION_SECONDS,
                    PORT_MAPPING_DESCRIPTION,
                )
                .await
                .is_ok()
            {
                return Ok(Mapping {
                    gateway,
                    external_ip,
                    external_port,
                    local_addr,
                });
            }
        }

        let external_port = gateway
            .add_any_port(
                igd::PortMappingProtocol::UDP,
                local_addr,
                PORT_MAPPING_LEASE_DURATION_SECONDS,
                PORT_MAPPING_DESCRIPTION,
            )
            .await?
            .try_into()
            .map_err(|_| anyhow::anyhow!("upnp mapping got zero external port"))?;

        Ok(Mapping {
            gateway,
            external_ip,
            external_port,
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
            external_port,
            ..
        } = self;
        gateway
            .remove_port(igd::PortMappingProtocol::UDP, external_port.into())
            .await?;
        Ok(())
    }

    // external indicates what port the mapping can be reached from on the outside.
    // TODO(@divma): docs
    pub fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        (self.external_ip, self.external_port)
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
            self.local_addr, self.external_port
        )
    }
}
