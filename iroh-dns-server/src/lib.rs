//! A DNS server and pkarr relay

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod config;
pub mod dns;
pub mod http;
pub mod metrics;
pub mod server;
pub mod state;
mod store;
mod util;

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use anyhow::Result;
    use hickory_resolver::{
        config::{NameServerConfig, Protocol, ResolverConfig},
        AsyncResolver,
    };
    use iroh_net::{
        discovery::pkarr_publish::PkarrRelayClient,
        dns::{
            node_info::{lookup_by_id, NodeInfo},
            DnsResolver,
        },
        key::SecretKey,
    };
    use url::Url;

    use crate::server::Server;

    #[tokio::test]
    async fn integration_smoke() -> Result<()> {
        tracing_subscriber::fmt::init();
        let (server, nameserver, http_url) = Server::spawn_for_tests().await?;
        println!("server spawned {nameserver} {http_url}");

        let pkarr_relay = {
            let mut url = http_url.clone();
            url.set_path("/pkarr");
            url
        };

        let origin = "irohdns.example.";

        let secret_key = SecretKey::generate();
        let node_id = secret_key.public();
        let relay_url: Url = "https://relay.example.".parse()?;
        let pkarr = PkarrRelayClient::new(pkarr_relay);
        let node_info = NodeInfo::new(node_id, Some(relay_url.clone()));
        let signed_packet = node_info.to_pkarr_signed_packet(&secret_key, 30)?;

        println!("now publish");
        pkarr.publish(&signed_packet).await?;
        println!("published");

        let resolver = test_resolver(nameserver);
        println!("now resolve");
        let resolved = lookup_by_id(&resolver, &node_id, origin).await?;
        println!("resolved {resolved:?}");
        assert_eq!(resolved.node_id, node_id);
        assert_eq!(
            resolved.info.relay_url.map(|u| Url::from(u)),
            Some(relay_url)
        );

        server.shutdown().await?;
        Ok(())
    }

    fn test_resolver(nameserver: SocketAddr) -> DnsResolver {
        let mut config = ResolverConfig::new();
        let nameserver_config = NameServerConfig::new(nameserver, Protocol::Udp);
        config.add_name_server(nameserver_config);
        AsyncResolver::tokio(config, Default::default())
    }
}
