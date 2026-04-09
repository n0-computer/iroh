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
        RelayUrl, SecretKey,
        address_lookup::PkarrRelayClient,
        dns::DnsResolver,
        endpoint_info::EndpointInfo,
        tls::{CaRootsConfig, default_provider},
    };
    use iroh_dns::{EndpointIdExt, pkarr::SignedPacket};
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;
    use rand::{CryptoRng, RngExt, SeedableRng};

    use crate::{
        ZoneStore,
        config::BootstrapOption,
        server::Server,
        store::{PacketSource, ZoneStoreOptions},
        util::PublicKeyBytes,
    };

    const DNS_TIMEOUT: Duration = Duration::from_secs(2);

    #[tokio::test]
    #[traced_test]
    async fn pkarr_publish_dns_resolve() -> Result {
        use simple_dns::{CLASS, Name as DnsName, Packet, ResourceRecord, rdata};

        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;
        let pkarr_relay_url = {
            let mut url = server.http_url().expect("http is bound");
            url.set_path("/pkarr");
            url
        };

        // Build a DNS packet with various record types using simple_dns directly
        let secret_key = SecretKey::generate();
        let origin = secret_key.public().to_z32();

        let mut packet = Packet::new_reply(0);
        // record at root
        packet.answers.push(ResourceRecord::new(
            DnsName::new_unchecked(&origin).into_owned(),
            CLASS::IN,
            30,
            rdata::RData::TXT("hi0".try_into().unwrap()),
        ));
        // record at level one
        packet.answers.push(ResourceRecord::new(
            DnsName::new_unchecked(&format!("_hello.{origin}")).into_owned(),
            CLASS::IN,
            30,
            rdata::RData::TXT("hi1".try_into().unwrap()),
        ));
        // record at level two
        packet.answers.push(ResourceRecord::new(
            DnsName::new_unchecked(&format!("_hello.world.{origin}")).into_owned(),
            CLASS::IN,
            30,
            rdata::RData::TXT("hi2".try_into().unwrap()),
        ));
        // multiple records for same name
        packet.answers.push(ResourceRecord::new(
            DnsName::new_unchecked(&format!("multiple.{origin}")).into_owned(),
            CLASS::IN,
            30,
            rdata::RData::TXT("hi3".try_into().unwrap()),
        ));
        packet.answers.push(ResourceRecord::new(
            DnsName::new_unchecked(&format!("multiple.{origin}")).into_owned(),
            CLASS::IN,
            30,
            rdata::RData::TXT("hi4".try_into().unwrap()),
        ));
        // record of type A
        packet.answers.push(ResourceRecord::new(
            DnsName::new_unchecked(&origin).into_owned(),
            CLASS::IN,
            30,
            rdata::RData::A(Ipv4Addr::LOCALHOST.into()),
        ));
        // record of type AAAA
        packet.answers.push(ResourceRecord::new(
            DnsName::new_unchecked(&format!("foo.bar.baz.{origin}")).into_owned(),
            CLASS::IN,
            30,
            rdata::RData::AAAA(Ipv6Addr::LOCALHOST.into()),
        ));

        // Encode and sign manually (same as pkarr format)
        let encoded = packet.build_bytes_vec_compressed().anyerr()?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let signable = {
            let mut s = format!("3:seqi{}e1:v{}:", timestamp, encoded.len()).into_bytes();
            s.extend(&encoded);
            s
        };
        let signature = secret_key.sign(&signable);
        let mut raw = Vec::with_capacity(104 + encoded.len());
        raw.extend_from_slice(secret_key.public().as_bytes());
        raw.extend_from_slice(&signature.to_bytes());
        raw.extend_from_slice(&timestamp.to_be_bytes());
        raw.extend_from_slice(&encoded);
        let signed_packet = SignedPacket::from_bytes(&raw).anyerr()?;

        // Publish via relay
        let tls_config = CaRootsConfig::default()
            .client_config(default_provider())
            .expect("infallible");
        let pkarr_client = PkarrRelayClient::new(pkarr_relay_url, tls_config);
        pkarr_client.publish(&signed_packet).await?;

        use hickory_server::proto::rr::Name;
        let pubkey = origin;
        let resolver = test_resolver(server.dns_addr());

        // resolve root record
        let name = Name::from_utf8(format!("{pubkey}.")).anyerr()?;
        let res = resolver.lookup_txt(name, DNS_TIMEOUT).await?;
        let records = res.into_iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi0".to_string()]);

        // resolve level one record
        let name = Name::from_utf8(format!("_hello.{pubkey}.")).anyerr()?;
        let res = resolver.lookup_txt(name, DNS_TIMEOUT).await?;
        let records = res.into_iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi1".to_string()]);

        // resolve level two record
        let name = Name::from_utf8(format!("_hello.world.{pubkey}.")).anyerr()?;
        let res = resolver.lookup_txt(name, DNS_TIMEOUT).await?;
        let records = res.into_iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi2".to_string()]);

        // resolve multiple records for same name
        let name = Name::from_utf8(format!("multiple.{pubkey}.")).anyerr()?;
        let res = resolver.lookup_txt(name, DNS_TIMEOUT).await?;
        let records = res.into_iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(records, vec!["hi3".to_string(), "hi4".to_string()]);

        // resolve A record
        let name = Name::from_utf8(format!("{pubkey}.")).anyerr()?;
        let res = resolver.lookup_ipv4(name, DNS_TIMEOUT).await?;
        let records = res.collect::<Vec<_>>();
        assert_eq!(records, vec![Ipv4Addr::LOCALHOST]);

        // resolve AAAA record
        let name = Name::from_utf8(format!("foo.bar.baz.{pubkey}.")).anyerr()?;
        let res = resolver.lookup_ipv6(name, DNS_TIMEOUT).await?;
        let records = res.collect::<Vec<_>>();
        assert_eq!(records, vec![Ipv6Addr::LOCALHOST]);

        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn integration_smoke() -> Result {
        let dir = tempfile::tempdir()?;
        let server = Server::spawn_for_tests(dir.path()).await?;

        let pkarr_relay = {
            let mut url = server.http_url().expect("http is bound");
            url.set_path("/pkarr");
            url
        };

        let origin = "irohdns.example.";

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        let secret_key = SecretKey::from_bytes(&rng.random());
        let endpoint_id = secret_key.public();
        let tls_config = CaRootsConfig::default()
            .client_config(default_provider())
            .expect("infallible");
        let pkarr = PkarrRelayClient::new(pkarr_relay, tls_config);
        let relay_url: RelayUrl = "https://relay.example.".parse()?;
        let endpoint_info = EndpointInfo::new(endpoint_id).with_relay_url(relay_url.clone());
        let signed_packet = endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?;

        pkarr.publish(&signed_packet).await?;

        let resolver = test_resolver(server.dns_addr());
        let res = resolver.lookup_endpoint_by_id(&endpoint_id, origin).await?;

        assert_eq!(res.endpoint_id, endpoint_id);
        assert_eq!(res.relay_urls().next(), Some(&relay_url));

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
    #[ignore = "flaky"]
    async fn integration_mainline() -> Result {
        let dir = tempfile::tempdir()?;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        // run a mainline testnet
        let testnet = mainline::Testnet::new_async(5).await.anyerr()?;
        let bootstrap = testnet.bootstrap.clone();

        // spawn our server with mainline support
        let server = Server::spawn_for_tests_with_options(
            dir.path(),
            Some(BootstrapOption::Custom(bootstrap.clone())),
            None,
            None,
        )
        .await?;

        let origin = "irohdns.example.";

        // create a signed packet
        let secret_key = SecretKey::from_bytes(&rng.random());
        let endpoint_id = secret_key.public();
        let relay_url: RelayUrl = "https://relay.example.".parse()?;
        let endpoint_info = EndpointInfo::new(endpoint_id).with_relay_url(relay_url.clone());
        let signed_packet = endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?;

        // publish to DHT using mainline directly
        let mut dht_builder = mainline::DhtBuilder::default();
        dht_builder.bootstrap(&bootstrap);
        let dht = dht_builder.build().anyerr()?;
        let item = mainline::MutableItem::new_signed_unchecked(
            *secret_key.public().as_bytes(),
            signed_packet.signature().to_bytes(),
            signed_packet.encoded_packet(),
            signed_packet.timestamp().as_micros() as i64,
            None,
        );
        dht.clone()
            .as_async()
            .put_mutable(item, None)
            .await
            .anyerr()?;

        // resolve via DNS from our server, which will lookup from our DHT
        let resolver = test_resolver(server.dns_addr());
        let res = resolver.lookup_endpoint_by_id(&endpoint_id, origin).await?;

        assert_eq!(res.endpoint_id, endpoint_id);
        assert_eq!(res.relay_urls().next(), Some(&relay_url));

        server.shutdown().await?;
        Ok(())
    }

    fn test_resolver(nameserver: SocketAddr) -> DnsResolver {
        DnsResolver::with_nameserver(nameserver)
    }

    fn random_signed_packet<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<SignedPacket> {
        let secret_key = SecretKey::from_bytes(&rng.random());
        let endpoint_id = secret_key.public();
        let relay_url: RelayUrl = "https://relay.example.".parse()?;
        let endpoint_info = EndpointInfo::new(endpoint_id).with_relay_url(relay_url.clone());
        let packet = endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?;
        Ok(packet)
    }
}
