//! Integration tests for relay connections over HTTP/3.

#[cfg(all(
    test,
    feature = "server",
    feature = "h3-transport",
    with_crypto_provider
))]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use iroh_base::{EndpointId, SecretKey};
    use n0_error::Result;
    use n0_future::{SinkExt, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};
    use tracing::{info, instrument};

    use crate::{
        KeyCache,
        client::{Client, ClientBuilder, conn::Conn, h3_conn},
        dns::DnsResolver,
        protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
        server::{
            AccessConfig, Metrics, Server,
            clients::Clients,
            h3_server::{H3RelayConfig, H3RelayServer},
            testing::self_signed_tls_certs_and_config,
        },
    };

    /// Spawn an H3-only relay server for testing.
    fn spawn_h3_relay() -> std::result::Result<H3RelayServer, crate::server::h3_server::H3SpawnError>
    {
        let (_, server_config) = self_signed_tls_certs_and_config();
        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        H3RelayServer::spawn(
            H3RelayConfig {
                bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                server_config,
                access: Arc::new(AccessConfig::Everyone),
                key_cache_capacity: 1024,
            },
            clients,
            metrics,
        )
    }

    /// Connect a relay client over H3 directly (no ClientBuilder).
    async fn connect_h3_client(
        server_addr: std::net::SocketAddr,
        secret_key: SecretKey,
    ) -> Result<Client> {
        let tls_config = crate::tls::make_dangerous_client_config();

        let (io, state, local_addr) =
            h3_conn::connect_h3(server_addr, "localhost", tls_config, &secret_key).await?;

        let conn = Conn::from_wt(io, state, KeyCache::new(128));
        Ok(Client::from_conn(conn, Some(local_addr)))
    }

    #[instrument]
    async fn try_send_recv(
        client_a: &mut Client,
        client_b: &mut Client,
        b_key: EndpointId,
        msg: Datagrams,
    ) -> Result<RelayToClientMsg> {
        for _ in 0..10 {
            client_a
                .send(ClientToRelayMsg::Datagrams {
                    dst_endpoint_id: b_key,
                    datagrams: msg.clone(),
                })
                .await?;
            let Ok(res) = tokio::time::timeout(Duration::from_millis(500), client_b.next()).await
            else {
                continue;
            };
            let res = res.expect("stream finished")?;
            return Ok(res);
        }
        panic!("failed to send and recv message");
    }

    fn dns_resolver() -> DnsResolver {
        DnsResolver::new()
    }

    /// Test with standalone H3 relay server and direct H3 clients.
    #[tokio::test]
    #[traced_test]
    async fn test_h3_relay_clients() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42u64);
        let server = spawn_h3_relay()?;
        let server_addr = server.bind_addr();

        info!(%server_addr, "H3 relay server started");

        let a_secret_key = SecretKey::from_bytes(&rng.random());
        let a_key = a_secret_key.public();
        let mut client_a = connect_h3_client(server_addr, a_secret_key).await?;

        let b_secret_key = SecretKey::from_bytes(&rng.random());
        let b_key = b_secret_key.public();
        let mut client_b = connect_h3_client(server_addr, b_secret_key).await?;

        // A -> B
        let msg = Datagrams::from("hello over h3, b!");
        let res = try_send_recv(&mut client_a, &mut client_b, b_key, msg.clone()).await?;
        let RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } = res
        else {
            panic!("unexpected message {res:?}");
        };
        assert_eq!(a_key, remote_endpoint_id);
        assert_eq!(msg, datagrams);

        // B -> A
        let msg = Datagrams::from("howdy over h3, a!");
        let res = try_send_recv(&mut client_b, &mut client_a, a_key, msg.clone()).await?;
        let RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } = res
        else {
            panic!("unexpected message {res:?}");
        };
        assert_eq!(b_key, remote_endpoint_id);
        assert_eq!(msg, datagrams);

        server.shutdown().await;
        Ok(())
    }

    /// Test H3 via `ClientBuilder::enable_h3(true)` against the full integrated server.
    #[tokio::test]
    #[traced_test]
    async fn test_h3_via_client_builder() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(99u64);

        // Spawn a full server with TLS (which auto-starts H3).
        let server = Server::spawn(crate::server::testing::server_config()).await?;
        let h3_addr = server.h3_addr().expect("H3 server should be running");

        info!(?h3_addr, "Full server with H3 started");

        let client_config = crate::tls::make_dangerous_client_config();

        // Use a relay URL pointing at the H3 address.
        let relay_url: iroh_base::RelayUrl =
            format!("https://localhost:{}", h3_addr.port()).parse()?;

        // Client A via H3
        let a_secret_key = SecretKey::from_bytes(&rng.random());
        let a_key = a_secret_key.public();
        let mut client_a = ClientBuilder::new(relay_url.clone(), a_secret_key, dns_resolver())
            .tls_client_config(client_config.clone())
            .enable_h3(true)
            .connect()
            .await?;

        // Verify H3 transport is actually used.
        assert_eq!(
            client_a.transport(),
            crate::client::Transport::H3,
            "Expected H3 transport"
        );

        // Client B via H3
        let b_secret_key = SecretKey::from_bytes(&rng.random());
        let b_key = b_secret_key.public();
        let mut client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, dns_resolver())
            .tls_client_config(client_config)
            .enable_h3(true)
            .connect()
            .await?;

        assert_eq!(
            client_b.transport(),
            crate::client::Transport::H3,
            "Expected H3 transport"
        );

        // A -> B
        let msg = Datagrams::from("h3 via builder!");
        let res = try_send_recv(&mut client_a, &mut client_b, b_key, msg.clone()).await?;
        let RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } = res
        else {
            panic!("unexpected message {res:?}");
        };
        assert_eq!(a_key, remote_endpoint_id);
        assert_eq!(msg, datagrams);

        server.shutdown().await?;
        Ok(())
    }

    /// Test that `enable_h3` falls back to WS when no H3 server is available.
    #[tokio::test]
    #[traced_test]
    async fn test_h3_fallback_to_ws() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(77u64);

        // Spawn a plain HTTP relay (no TLS, no H3).
        let server = Server::spawn(crate::server::ServerConfig::<(), ()> {
            relay: Some(crate::server::RelayConfig::<(), ()> {
                http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                tls: None,
                limits: Default::default(),
                key_cache_capacity: Some(1024),
                access: AccessConfig::Everyone,
            }),
            quic: None,
            metrics_addr: None,
        })
        .await?;

        let relay_url: iroh_base::RelayUrl =
            format!("http://{}", server.http_addr().unwrap()).parse()?;

        let client_config = crate::tls::make_dangerous_client_config();

        let a_secret_key = SecretKey::from_bytes(&rng.random());
        // enable_h3 is true but server has no H3, should fall back to WS.
        let client_a = ClientBuilder::new(relay_url, a_secret_key, dns_resolver())
            .tls_client_config(client_config)
            .enable_h3(true)
            .connect()
            .await?;

        assert_eq!(
            client_a.transport(),
            crate::client::Transport::Ws,
            "Should have fallen back to WS"
        );

        server.shutdown().await?;
        Ok(())
    }
}
