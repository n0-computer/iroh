use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};

use crate::resolver::Path;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Config {
    /// Mapping from TLD to the specific instance of resolver
    tld_resolvers: Option<HashMap<String, ResolverConfig>>,
}

impl Config {
    pub fn empty() -> Self {
        Config {
            tld_resolvers: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            /// Documentation on .eth TLD lives on https://eth.link/
            tld_resolvers: Some(HashMap::from_iter(vec![(
                "eth".to_string(),
                ResolverConfig::from_parts(
                    None,
                    vec![],
                    NameServerConfigGroup::from_ips_https(
                        &[
                            IpAddr::V4(Ipv4Addr::new(104, 18, 165, 219)),
                            IpAddr::V4(Ipv4Addr::new(104, 18, 166, 219)),
                        ],
                        443,
                        "resolver.cloudflare-eth.com".to_string(),
                        true,
                    ),
                ),
            )])),
        }
    }
}

#[derive(Debug)]
pub struct DnsResolver {
    default_resolver: TokioAsyncResolver,
    tld_resolvers: Option<HashMap<String, TokioAsyncResolver>>,
}

impl DnsResolver {
    /// Creates resolver from its config
    pub fn from_config(dns_resolver_config: Config) -> DnsResolver {
        let tld_resolvers = dns_resolver_config
            .tld_resolvers
            .map(|dns_resolver_config| {
                dns_resolver_config
                    .into_iter()
                    .map(|(tld, config)| {
                        (
                            tld,
                            AsyncResolver::tokio(config, ResolverOpts::default()).unwrap(),
                        )
                    })
                    .collect::<HashMap<_, _>>()
            });
        DnsResolver {
            default_resolver: AsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default(),
            )
            .unwrap(),
            tld_resolvers,
        }
    }

    #[tracing::instrument]
    pub async fn resolve_dnslink(&self, url: &str) -> Result<Vec<Path>> {
        let url = format!("_dnslink.{url}.");
        let records = self.resolve_txt_record(&url).await?;
        let records = records
            .into_iter()
            .filter(|r| r.starts_with("dnslink="))
            .map(|r| {
                let p = r.trim_start_matches("dnslink=").trim();
                p.parse()
            })
            .collect::<Result<_>>()?;
        Ok(records)
    }

    pub async fn resolve_txt_record(&self, url: &str) -> Result<Vec<String>> {
        let tld = url.split('.').filter(|s| !s.is_empty()).last();
        let resolver = tld
            .and_then(|tld| {
                self.tld_resolvers
                    .as_ref()
                    .and_then(|tld_resolvers| tld_resolvers.get(tld))
            })
            .unwrap_or(&self.default_resolver);
        let txt_response = resolver.txt_lookup(url).await?;
        let out = txt_response.into_iter().map(|r| r.to_string()).collect();
        Ok(out)
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        DnsResolver::from_config(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::DnsResolver;
    use crate::resolver::PathType;

    #[tokio::test]
    async fn test_resolve_txt_record() {
        let resolver = DnsResolver::default();
        let result = resolver
            .resolve_txt_record("_dnslink.ipfs.io.")
            .await
            .unwrap();
        assert!(!result.is_empty());
        assert_eq!(result[0], "dnslink=/ipns/website.ipfs.io");

        let result = resolver
            .resolve_txt_record("_dnslink.website.ipfs.io.")
            .await
            .unwrap();
        assert!(!result.is_empty());
        assert!(&result[0].starts_with("dnslink=/ipfs"));
    }

    #[tokio::test]
    async fn test_resolve_dnslink() {
        let resolver = DnsResolver::default();
        let result = resolver.resolve_dnslink("ipfs.io").await.unwrap();
        assert!(!result.is_empty());
        assert_eq!(result[0], "/ipns/website.ipfs.io".parse().unwrap());

        let result = resolver.resolve_dnslink("website.ipfs.io").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].typ(), PathType::Ipfs);
    }

    #[tokio::test]
    async fn test_resolve_eth_domain() {
        let resolver = DnsResolver::default();
        let result = resolver.resolve_dnslink("ipfs.eth").await.unwrap();
        assert!(!result.is_empty());
        assert_eq!(result[0].typ(), PathType::Ipfs);
    }
}
