//! System DNS configuration from the Apple SystemConfiguration framework.
//!
//! Used on all Apple platforms (macOS, iOS, tvOS, watchOS). They do not keep
//! `/etc/resolv.conf` in sync with the live resolver configuration (and on iOS
//! the sandbox hides it entirely), so reading that file (as the generic Unix
//! reader does) can miss the nameservers the system is actually using. Instead
//! we read the primary resolver from the dynamic store key
//! `State:/Network/Global/DNS`, the way the old hickory-resolver path did on
//! Apple targets. That key holds the default resolver's `ServerAddresses` and
//! `SearchDomains`. Scoped per-domain resolvers (VPN split-DNS) live under
//! other keys and were not read by the old path either.

use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::{FromVoid, ItemRef, TCFType},
        dictionary::CFDictionary,
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};
use tracing::warn;

use super::{DNS_PORT, DnsConfig, DnsProtocol, Nameserver};

/// Reads the primary system DNS configuration from SystemConfiguration.
pub(super) fn read_system_dns() -> Result<DnsConfig, std::io::Error> {
    let store = SCDynamicStoreBuilder::new("iroh-dns")
        .build()
        .ok_or_else(|| {
            std::io::Error::other("failed to access SystemConfiguration dynamic store")
        })?;
    let dns_cfg = store
        .get("State:/Network/Global/DNS")
        .and_then(|value| value.downcast_into::<CFDictionary>())
        .ok_or_else(|| std::io::Error::other("no DNS dictionary in SystemConfiguration"))?;

    let nameservers = read_string_array(&dns_cfg, "ServerAddresses")
        .into_iter()
        .filter_map(|s| match IpAddr::from_str(&s) {
            Ok(ip) => Some(Nameserver::new(
                SocketAddr::new(ip, DNS_PORT),
                DnsProtocol::Udp,
            )),
            Err(err) => {
                warn!(nameserver = %s, %err, "ignoring unparsable nameserver from SystemConfiguration");
                None
            }
        })
        .collect();

    let search_domains = read_string_array(&dns_cfg, "SearchDomains");

    Ok(DnsConfig {
        nameservers,
        search_domains,
        ndots: None,
    })
}

/// Reads a `CFArray`-of-`CFString` value from `dict` by key, returning the
/// strings. Returns an empty vector when the key is absent.
fn read_string_array(dict: &CFDictionary, key: &'static str) -> Vec<String> {
    let Some(value) = dict.find(CFString::from_static_string(key).as_CFTypeRef()) else {
        return Vec::new();
    };
    // SAFETY: the SystemConfiguration DNS dictionary stores ServerAddresses and
    // SearchDomains as CFArrays of CFString, per the documented schema. See
    // https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnsserveraddresses-swift.var
    let array: ItemRef<'_, CFArray<CFString>> = unsafe { CFArray::from_void(*value) };
    let mut out = Vec::with_capacity(array.len() as usize);
    for item in &*array {
        out.push(Cow::from(&*item).into_owned());
    }
    out
}
