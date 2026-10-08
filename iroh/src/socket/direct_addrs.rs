//! Combines direct-address candidates while preserving source precedence.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{SocketAddr, SocketAddrV4},
};

use super::{DirectAddr, DirectAddrType};
use crate::net_report::PublicAddrs;

/// Collects each address once, preferring portmapped, QAD, local, then configured sources.
pub(super) fn collect(
    port_mapped: Option<SocketAddrV4>,
    public: PublicAddrs,
    bound: &[SocketAddr],
    local: impl IntoIterator<Item = SocketAddr>,
    configured: impl IntoIterator<Item = SocketAddr>,
) -> BTreeSet<DirectAddr> {
    let mut addrs = BTreeMap::new();
    if let Some(addr) = port_mapped {
        addrs.insert(SocketAddr::V4(addr), DirectAddrType::Portmapped);
    }
    if let Some(v4) = public.v4 {
        addrs.entry(v4.addr.into()).or_insert(DirectAddrType::Qad);
        // A fixed local port may also have a static router mapping behind a hard NAT.
        if v4.varies_by_dest
            && let Some(port) = bound
                .iter()
                .find_map(|addr| (addr.port() != 0).then_some(addr.port()))
        {
            let mut addr = v4.addr;
            addr.set_port(port);
            addrs
                .entry(addr.into())
                .or_insert(DirectAddrType::Qad4LocalPort);
        }
    }
    if let Some(v6) = public.v6 {
        addrs.entry(v6.addr.into()).or_insert(DirectAddrType::Qad);
    }
    for addr in local {
        addrs.entry(addr).or_insert(DirectAddrType::Local);
    }
    for addr in configured {
        addrs.entry(addr).or_insert(DirectAddrType::Config);
    }
    addrs
        .into_iter()
        .map(|(addr, typ)| DirectAddr { addr, typ })
        .collect()
}
