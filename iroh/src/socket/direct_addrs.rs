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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_precedence_and_hard_nat_candidate() {
        let external: SocketAddrV4 = "198.51.100.1:45000".parse().unwrap();
        let local: SocketAddr = "192.0.2.1:7777".parse().unwrap();
        let configured: SocketAddr = "203.0.113.1:9999".parse().unwrap();
        let public = PublicAddrs {
            v4: Some(crate::net_report::PublicAddr {
                addr: external,
                varies_by_dest: true,
            }),
            v6: None,
        };
        let actual = collect(
            Some(external),
            public,
            &["0.0.0.0:7777".parse().unwrap()],
            [external.into(), local],
            [external.into(), local, configured],
        );
        let expected = [
            DirectAddr {
                addr: external.into(),
                typ: DirectAddrType::Portmapped,
            },
            DirectAddr {
                addr: "198.51.100.1:7777".parse().unwrap(),
                typ: DirectAddrType::Qad4LocalPort,
            },
            DirectAddr {
                addr: local,
                typ: DirectAddrType::Local,
            },
            DirectAddr {
                addr: configured,
                typ: DirectAddrType::Config,
            },
        ]
        .into_iter()
        .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_ephemeral_bind_has_no_fixed_port_candidate() {
        let external: SocketAddrV4 = "198.51.100.1:45000".parse().unwrap();
        let public = PublicAddrs {
            v4: Some(crate::net_report::PublicAddr {
                addr: external,
                varies_by_dest: true,
            }),
            v6: None,
        };
        assert_eq!(
            collect(None, public, &["0.0.0.0:0".parse().unwrap()], [], []),
            [DirectAddr {
                addr: external.into(),
                typ: DirectAddrType::Qad
            }]
            .into_iter()
            .collect(),
        );
    }
}
