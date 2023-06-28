use std::{
    fmt::Display,
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    time::{Duration, Instant},
};

use anyhow::Result;
use igd::aio as aigd;

/// Seconds we ask the router to maintain the port mapping. 0 means infinite.
const PORT_MAPPING_LEASE_DURATION_SECONDS: u32 = 0;

/// Maximum duration a UPnP search can take before timing out.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(5);

const PORT_MAPPING_DESCRIPTION: &str = "iroh-portmap";

#[derive(Debug, Clone)]
pub struct Mapping {
    /// The internet Gateway device (router) used to create this mapping.
    gateway: aigd::Gateway,
    /// The external address obtained by this mapping.
    external_addr: SocketAddrV4,
    /// Local address used to create this mapping.
    local_addr: SocketAddrV4,
    /// Instant in which the mapping was first created or last renewed.
    created_at: Instant,
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
            created_at: Instant::now(),
        })
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

    /// good_until will return the lease time that the mapping is valid for.
    pub fn good_until(&self) -> Instant {
        // assume an hour
        self.created_at + Duration::from_secs(60 * 60)
    }
    /// renew_after returns the earliest time that the mapping should be renewed.
    pub fn renew_after(&self) -> Instant {
        // 55 minutes
        self.created_at + Duration::from_secs(60 * 55)
    }

    // external indicates what port the mapping can be reached from on the outside.
    pub fn external(&self) -> SocketAddrV4 {
        self.external_addr
    }
}

/// Searchs for upnp gateways, returns the [`SocketAddrV4`] if any was found.
pub async fn probe_available() -> Result<SocketAddrV4> {
    let gateway = aigd::search_gateway(igd::SearchOptions {
        timeout: Some(SEARCH_TIMEOUT),
        ..Default::default()
    })
    .await?;
    Ok(gateway.addr)
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
