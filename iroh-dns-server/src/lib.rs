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
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

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
    use pkarr::SignedPacket;
    use url::Url;

    use crate::server::Server;

    #[tokio::test]
    async fn pkarr_publish_dns_resolve() -> Result<()> {
        iroh_test::logging::setup_multithreaded();
        let (server, nameserver, http_url) = Server::spawn_for_tests().await?;
        let pkarr_relay_url = {
            let mut url = http_url.clone();
            url.set_path("/pkarr");
            url
        };
        let signed_packet = {
            use pkarr::dns;
            let keypair = pkarr::Keypair::random();
            let mut packet = dns::Packet::new_reply(0);
            // record at root
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi0".try_into()?),
            ));
            // record at level one
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("_hello").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi1".try_into()?),
            ));
            // record at level two
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("_hello.world").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi2".try_into()?),
            ));
            // multiple records for same name
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("multiple").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi3".try_into()?),
            ));
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("multiple").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi4".try_into()?),
            ));
            // record of type A
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::A(Ipv4Addr::LOCALHOST.into()),
            ));
            // record of type AAAA
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("foo.bar.baz").unwrap(),
                dns::CLASS::IN,
                30,
                dns::rdata::RData::AAAA(Ipv6Addr::LOCALHOST.into()),
            ));
            SignedPacket::from_packet(&keypair, &packet)?
        };
        let pkarr_client = pkarr::PkarrClient::builder().build();
        pkarr_client
            .relay_put(&pkarr_relay_url, &signed_packet)
            .await?;

        use hickory_proto::rr::Name;
        let pubkey = signed_packet.public_key().to_z32();
        let resolver = test_resolver(nameserver);

        // resolve root record
        let name = Name::from_utf8(format!("{pubkey}."))?;
        let res = resolver.txt_lookup(name).await?;
        let records = res.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi0".to_string()]);

        // resolve level one record
        let name = Name::from_utf8(format!("_hello.{pubkey}."))?;
        let res = resolver.txt_lookup(name).await?;
        let records = res.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi1".to_string()]);

        // resolve level two record
        let name = Name::from_utf8(format!("_hello.world.{pubkey}."))?;
        let res = resolver.txt_lookup(name).await?;
        let records = res.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi2".to_string()]);

        // resolve multiple records for same name
        let name = Name::from_utf8(format!("multiple.{pubkey}."))?;
        let res = resolver.txt_lookup(name).await?;
        let records = res.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi3".to_string(), "hi4".to_string()]);

        // resolve A record
        let name = Name::from_utf8(format!("{pubkey}."))?;
        let res = resolver.ipv4_lookup(name).await?;
        let records = res.iter().map(|t| t.0).collect::<Vec<_>>();
        assert_eq!(records, vec![Ipv4Addr::LOCALHOST]);

        // resolve AAAA record
        let name = Name::from_utf8(format!("foo.bar.baz.{pubkey}."))?;
        let res = resolver.ipv6_lookup(name).await?;
        let records = res.iter().map(|t| t.0).collect::<Vec<_>>();
        assert_eq!(records, vec![Ipv6Addr::LOCALHOST]);

        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn integration_smoke() -> Result<()> {
        iroh_test::logging::setup_multithreaded();
        let (server, nameserver, http_url) = Server::spawn_for_tests().await?;

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

        pkarr.publish(&signed_packet).await?;

        let resolver = test_resolver(nameserver);
        let res = lookup_by_id(&resolver, &node_id, origin).await?;

        assert_eq!(res.node_id, node_id);
        assert_eq!(res.info.relay_url.map(Url::from), Some(relay_url));

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
