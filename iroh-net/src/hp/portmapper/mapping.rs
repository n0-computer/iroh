use std::{net::Ipv4Addr, num::NonZeroU16, time::Duration};

use anyhow::Result;

use super::{nat_pmp, pcp, upnp};

pub(super) trait PortMapped: std::fmt::Debug + Unpin {
    fn external(&self) -> (Ipv4Addr, NonZeroU16);
    /// Half the lifetime of a mapping. This is used to calculate when a mapping should be renewed.
    fn half_lifetime(&self) -> Duration;
    fn release(self) -> Result<()>;
}

#[derive(derive_more::Debug)]
pub enum Mapping {
    #[debug(transparent)]
    Upnp(upnp::Mapping),
    #[debug(transparent)]
    Pcp(pcp::Mapping),
    #[debug(transparent)]
    NatPmp(nat_pmp::Mapping),
}
impl Mapping {
    pub(crate) async fn new_pcp(
        local_ip: Ipv4Addr,
        local_port: NonZeroU16,
        gateway: Ipv4Addr,
        external_addr: Option<(Ipv4Addr, NonZeroU16)>,
    ) -> Result<Self> {
        todo!()
    }

    pub(crate) async fn new_nat_pmp(
        local_ip: Ipv4Addr,
        local_port: NonZeroU16,
        gateway: Ipv4Addr,
        external_addr: Option<(Ipv4Addr, NonZeroU16)>,
    ) -> Result<Self> {
        todo!()
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
}

impl PortMapped for Mapping {
    fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        match self {
            Mapping::Upnp(m) => m.external(),
            Mapping::Pcp(m) => m.external(),
            Mapping::NatPmp(m) => m.external(),
        }
    }

    fn half_lifetime(&self) -> Duration {
        match self {
            Mapping::Upnp(m) => m.half_lifetime(),
            Mapping::Pcp(m) => m.half_lifetime(),
            Mapping::NatPmp(m) => m.half_lifetime(),
        }
    }

    fn release(self) -> Result<()> {
        match self {
            Mapping::Upnp(m) => todo!(),
            Mapping::Pcp(m) => m.release(),
            Mapping::NatPmp(m) => m.release(),
        }
    }
}
