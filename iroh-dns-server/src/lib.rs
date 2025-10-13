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

// Re-export to be able to construct your own dns-server
pub use store::ZoneStore;

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use iroh::{
        RelayUrl, SecretKey, discovery::pkarr::PkarrRelayClient, dns::DnsResolver,
        node_info::NodeInfo,
    };
    use n0_snafu::{Result, ResultExt};
    use pkarr::{SignedPacket, Timestamp};
    use rand::{CryptoRng, SeedableRng};
    use tracing_test::traced_test;

    use crate::{
        ZoneStore,
        config::BootstrapOption,
        server::Server,
        store::{PacketSource, ZoneStoreOptions},
        util::PublicKeyBytes,
    };

    const DNS_TIMEOUT: Duration = Duration::from_secs(1);

    #[tokio::test]
    #[traced_test]
    async fn pkarr_publish_dns_resolve() -> Result {
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
                dns::Name::new("").e()?,
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi0".try_into().unwrap()),
            ));
            // record at level one
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("_hello").e()?,
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi1".try_into().unwrap()),
            ));
            // record at level two
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("_hello.world").e()?,
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi2".try_into().unwrap()),
            ));
            // multiple records for same name
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("multiple").e()?,
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi3".try_into().unwrap()),
            ));
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("multiple").e()?,
                dns::CLASS::IN,
                30,
                dns::rdata::RData::TXT("hi4".try_into().unwrap()),
            ));
            // record of type A
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("").e()?,
                dns::CLASS::IN,
                30,
                dns::rdata::RData::A(Ipv4Addr::LOCALHOST.into()),
            ));
            // record of type AAAA
            packet.answers.push(dns::ResourceRecord::new(
                dns::Name::new("foo.bar.baz").e()?,
                dns::CLASS::IN,
                30,
                dns::rdata::RData::AAAA(Ipv6Addr::LOCALHOST.into()),
            ));
            SignedPacket::new(&keypair, &packet.answers, Timestamp::now()).e()?
        };
        let pkarr_client = pkarr::Client::builder()
            .no_default_network()
            .relays(&[pkarr_relay_url])
            .e()?
            .build()
            .e()?;
        pkarr_client.publish(&signed_packet, None).await.e()?;

        use hickory_server::proto::rr::Name;
        let pubkey = signed_packet.public_key().to_z32();
        let resolver = test_resolver(nameserver);

        // resolve root record
        let name = Name::from_utf8(format!("{pubkey}.")).e()?;
        let res = resolver.lookup_txt(name, DNS_TIMEOUT).await?;
        let records = res.into_iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi0".to_string()]);

        // resolve level one record
        let name = Name::from_utf8(format!("_hello.{pubkey}.")).e()?;
        let res = resolver.lookup_txt(name, DNS_TIMEOUT).await?;
        let records = res.into_iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi1".to_string()]);

        // resolve level two record
        let name = Name::from_utf8(format!("_hello.world.{pubkey}.")).e()?;
        let res = resolver.lookup_txt(name, DNS_TIMEOUT).await?;
        let records = res.into_iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi2".to_string()]);

        // resolve multiple records for same name
        let name = Name::from_utf8(format!("multiple.{pubkey}.")).e()?;
        let res = resolver.lookup_txt(name, DNS_TIMEOUT).await?;
        let records = res.into_iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi3".to_string(), "hi4".to_string()]);

        // resolve A record
        let name = Name::from_utf8(format!("{pubkey}.")).e()?;
        let res = resolver.lookup_ipv4(name, DNS_TIMEOUT).await?;
        let records = res.collect::<Vec<_>>();
        assert_eq!(records, vec![Ipv4Addr::LOCALHOST]);

        // resolve AAAA record
        let name = Name::from_utf8(format!("foo.bar.baz.{pubkey}.")).e()?;
        let res = resolver.lookup_ipv6(name, DNS_TIMEOUT).await?;
        let records = res.collect::<Vec<_>>();
        assert_eq!(records, vec![Ipv6Addr::LOCALHOST]);

        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn integration_smoke() -> Result {
        let (server, nameserver, http_url) = Server::spawn_for_tests().await?;

        let pkarr_relay = {
            let mut url = http_url.clone();
            url.set_path("/pkarr");
            url
        };

        let origin = "irohdns.example.";

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let secret_key = SecretKey::generate(&mut rng);
        let node_id = secret_key.public();
        let pkarr = PkarrRelayClient::new(pkarr_relay);
        let relay_url: RelayUrl = "https://relay.example.".parse()?;
        let node_info = NodeInfo::new(node_id).with_relay_url(Some(relay_url.clone()));
        let signed_packet = node_info.to_pkarr_signed_packet(&secret_key, 30)?;

        pkarr.publish(&signed_packet).await?;

        let resolver = test_resolver(nameserver);
        let res = resolver.lookup_node_by_id(&node_id, origin).await?;

        assert_eq!(res.node_id, node_id);
        assert_eq!(res.relay_url(), Some(&relay_url));

        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn store_eviction() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let options = ZoneStoreOptions {
            eviction: Duration::from_millis(100),
            eviction_interval: Duration::from_millis(100),
            max_batch_time: Duration::from_millis(100),
            ..Default::default()
        };
        let store = ZoneStore::in_memory(options, Default::default())?;

        // create a signed packet
        let signed_packet = random_signed_packet(&mut rng)?;
        let key = PublicKeyBytes::from_signed_packet(&signed_packet);

        store
            .insert(signed_packet, PacketSource::PkarrPublish)
            .await?;

        tokio::time::sleep(Duration::from_secs(1)).await;
        for _ in 0..10 {
            let entry = store.get_signed_packet(&key).await?;
            if entry.is_none() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!("store did not evict packet");
    }

    #[tokio::test]
    #[traced_test]
    async fn integration_mainline() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        // run a mainline testnet
        let testnet = pkarr::mainline::Testnet::new_async(5).await.e()?;
        let bootstrap = testnet.bootstrap.clone();

        // spawn our server with mainline support
        let (server, nameserver, _http_url) =
            Server::spawn_for_tests_with_options(Some(BootstrapOption::Custom(bootstrap)), None)
                .await?;

        let origin = "irohdns.example.";

        // create a signed packet
        let secret_key = SecretKey::generate(&mut rng);
        let node_id = secret_key.public();
        let relay_url: RelayUrl = "https://relay.example.".parse()?;
        let node_info = NodeInfo::new(node_id).with_relay_url(Some(relay_url.clone()));
        let signed_packet = node_info.to_pkarr_signed_packet(&secret_key, 30)?;

        // publish the signed packet to our DHT
        let pkarr = pkarr::Client::builder()
            .no_default_network()
            .dht(|builder| builder.bootstrap(&testnet.bootstrap))
            .build()
            .e()?;
        pkarr.publish(&signed_packet, None).await.e()?;

        // resolve via DNS from our server, which will lookup from our DHT
        let resolver = test_resolver(nameserver);
        let res = resolver.lookup_node_by_id(&node_id, origin).await?;

        assert_eq!(res.node_id, node_id);
        assert_eq!(res.relay_url(), Some(&relay_url));

        server.shutdown().await?;
        Ok(())
    }

    fn test_resolver(nameserver: SocketAddr) -> DnsResolver {
        DnsResolver::with_nameserver(nameserver)
    }

    fn random_signed_packet<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<SignedPacket> {
        let secret_key = SecretKey::generate(rng);
        let node_id = secret_key.public();
        let relay_url: RelayUrl = "https://relay.example.".parse()?;
        let node_info = NodeInfo::new(node_id).with_relay_url(Some(relay_url.clone()));
        let packet = node_info.to_pkarr_signed_packet(&secret_key, 30)?;
        Ok(packet)
    }
}
