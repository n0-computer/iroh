use std::net::{Ipv4Addr, Ipv6Addr};

use iroh_dns::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};
use n0_future::boxed::BoxFuture;

/// Resolver that hands out fixed IPv4 and IPv6 addresses for every host.
#[derive(Debug, Clone)]
pub(crate) struct StaticResolver {
    v4: Vec<Ipv4Addr>,
    v6: Vec<Ipv6Addr>,
}

impl Resolver for StaticResolver {
    fn lookup_ipv4(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        let addrs: BoxIter<_> = Box::new(self.v4.clone().into_iter());
        Box::pin(std::future::ready(Ok(addrs)))
    }

    fn lookup_ipv6(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        let addrs: BoxIter<_> = Box::new(self.v6.clone().into_iter());
        Box::pin(std::future::ready(Ok(addrs)))
    }

    fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        let records: BoxIter<_> = Box::new(std::iter::empty());
        Box::pin(std::future::ready(Ok(records)))
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(self.clone())
    }
}

impl StaticResolver {
    pub(crate) fn new(v4: Vec<Ipv4Addr>, v6: Vec<Ipv6Addr>) -> DnsResolver {
        DnsResolver::custom(StaticResolver { v4, v6 })
    }
}
