use std::{net::Ipv4Addr, num::NonZeroU16, time::Duration};

use anyhow::Result;

use super::{pcp, upnp};

pub(super) trait PortMapped: std::fmt::Debug + Unpin {
    fn external(&self) -> (Ipv4Addr, NonZeroU16);
    /// Half the lifetime of a mapping. This is used to calculate when a mapping should be renewed.
    fn half_lifetime(&self) -> Duration;
}

#[derive(derive_more::Debug)]
pub enum Mapping {
    #[debug(transparent)]
    Upnp(upnp::Mapping),
    #[debug(transparent)]
    Pcp(pcp::Mapping),
}
impl Mapping {
    pub(crate) async fn new_pcp(
        local_ip: Ipv4Addr,
        local_port: NonZeroU16,
        gateway: Ipv4Addr,
        external_addr: Option<(Ipv4Addr, NonZeroU16)>,
    ) -> Result<Self> {
        pcp::Mapping::new(local_ip, local_port, gateway, external_addr)
            .await
            .map(Self::Pcp)
    }

    pub(crate) async fn new_upnp(
        local_ip: Ipv4Addr,
        local_port: NonZeroU16,
        gateway: Option<igd::aio::Gateway>,
        external_port: Option<NonZeroU16>,
    ) -> Result<Self> {
        upnp::Mapping::new(local_ip, local_port, gateway, external_port)
            .await
            .map(Self::Upnp)
    }

    pub(crate) async fn release(self) -> Result<()> {
        match self {
            Mapping::Upnp(m) => m.release().await,
            Mapping::Pcp(m) => {
                // TODO(@divma): do
                anyhow::bail!("unimplemented");
            }
        }
    }
}

impl PortMapped for Mapping {
    fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        match self {
            Mapping::Upnp(m) => m.external(),
            Mapping::Pcp(m) => m.external(),
        }
    }

    fn half_lifetime(&self) -> Duration {
        match self {
            Mapping::Upnp(m) => m.half_lifetime(),
            Mapping::Pcp(m) => m.half_lifetime(),
        }
    }
}
