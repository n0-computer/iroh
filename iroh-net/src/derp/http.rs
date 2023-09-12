//! An http specific DERP Client and DERP Server. Allows for using tls or non tls connection
//! upgrades.
//!
//! For each remote http DERP Server in a given http DERP Server's region, that it can mesh with, the
//! DERP Server will have one http DERP Client that is connected to each other http DERP Server in the
//! region. Those http DERP Clients will act as `PacketForwarder`s for the remote http DERP Servers.
//!
mod client;
mod mesh_clients;
mod server;

pub use self::client::{Client, ClientBuilder, ClientError};
pub use self::mesh_clients::MeshAddrs;
pub use self::server::{Server, ServerBuilder, TlsAcceptor, TlsConfig};

pub(crate) const HTTP_UPGRADE_PROTOCOL: &str = "iroh derp http";

#[cfg(test)]
pub(crate) fn make_tls_config() -> (TlsConfig, rustls::Certificate) {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];

    let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
    let rustls_certificate = rustls::Certificate(cert.serialize_der().unwrap());
    let rustls_key = rustls::PrivateKey(cert.get_key_pair().serialize_der());
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![(rustls_certificate.clone())], rustls_key)
        .unwrap();

    let config = std::sync::Arc::new(config);
    let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());

    (
        TlsConfig {
            config,
            acceptor: TlsAcceptor::Manual(acceptor),
        },
        rustls_certificate,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use bytes::Bytes;
    use reqwest::Url;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tracing::{info_span, Instrument};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use crate::derp::{DerpNode, DerpRegion, ReceivedMessage, UseIpv4, UseIpv6};
    use crate::key::{PublicKey, SecretKey};

    #[tokio::test]
    async fn test_http_clients_and_server() -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();

        let server_key = SecretKey::generate();
        let a_key = SecretKey::generate();
        let b_key = SecretKey::generate();

        // start server
        let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(server_key))
            .spawn()
            .await?;

        let addr = server.addr();

        // get dial info & create region
        let port = addr.port();
        let addr = {
            if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
                ipv4_addr
            } else {
                anyhow::bail!("cannot get ipv4 addr from socket addr {addr:?}");
            }
        };
        println!("addr: {addr}:{port}");
        let region = DerpRegion {
            region_id: 1,
            avoid: false,
            nodes: vec![DerpNode {
                name: "test_node".to_string(),
                region_id: 1,
                url: format!("http://localhost:{port}").parse().unwrap(),
                stun_only: false,
                stun_port: 0,
                ipv4: UseIpv4::Some(addr),
                ipv6: UseIpv6::Disabled,
            }
            .into()],
            region_code: "test_region".to_string(),
        };

        // create clients
        let derp_addr: Url = format!("http://{addr}:{port}").parse().unwrap();
        let (a_key, mut a_recv, client_a_task, client_a) =
            create_test_client(a_key, region.clone(), Some(derp_addr.clone()));
        println!("created client {a_key:?}");
        let (b_key, mut b_recv, client_b_task, client_b) =
            create_test_client(b_key, region, Some(derp_addr));
        println!("created client {b_key:?}");

        client_a.ping().await?;
        client_b.ping().await?;

        println!("sending message from a to b");
        let msg = Bytes::from_static(b"hi there, client b!");
        client_a.send(b_key, msg.clone()).await?;
        println!("waiting for message from a on b");
        let (got_key, got_msg) = b_recv.recv().await.expect("expected message from client_a");
        assert_eq!(a_key, got_key);
        assert_eq!(msg, got_msg);

        println!("sending message from b to a");
        let msg = Bytes::from_static(b"right back at ya, client b!");
        client_b.send(a_key, msg.clone()).await?;
        println!("waiting for message b on a");
        let (got_key, got_msg) = a_recv.recv().await.expect("expected message from client_b");
        assert_eq!(b_key, got_key);
        assert_eq!(msg, got_msg);

        server.shutdown().await;
        client_a.close().await;
        client_a_task.abort();
        client_b.close().await;
        client_b_task.abort();
        Ok(())
    }

    fn create_test_client(
        key: SecretKey,
        region: DerpRegion,
        server_url: Option<Url>,
    ) -> (
        PublicKey,
        mpsc::Receiver<(PublicKey, Bytes)>,
        JoinHandle<()>,
        Client,
    ) {
        let mut client = ClientBuilder::new();
        if let Some(url) = server_url {
            client = client.server_url(url);
        }
        let client = client
            .get_region(move || {
                let region = region.clone();
                Box::pin(async move { Some(region) })
            })
            .build(key.clone())
            .expect("won't fail if you supply a `get_region`");
        let public_key = key.public();
        let (received_msg_s, received_msg_r) = tokio::sync::mpsc::channel(10);
        let client_reader = client.clone();
        let client_reader_task = tokio::spawn(
            async move {
                loop {
                    println!("waiting for message on {:?}", key.public());
                    match client_reader.recv_detail().await {
                        Err(e) => {
                            println!("client {:?} `recv_detail` error {e}", key.public());
                            return;
                        }
                        Ok((msg, _)) => {
                            println!("got message on {:?}: {msg:?}", key.public());
                            if let ReceivedMessage::ReceivedPacket { source, data } = msg {
                                received_msg_s
                                    .send((source, data))
                                    .await
                                    .unwrap_or_else(|err| {
                                        panic!(
                                            "client {:?}, error sending message over channel: {:?}",
                                            key.public(),
                                            err
                                        )
                                    });
                            }
                        }
                    }
                }
            }
            .instrument(info_span!("test.client.reader")),
        );
        (public_key, received_msg_r, client_reader_task, client)
    }

    #[tokio::test]
    async fn test_https_clients_and_server() -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();

        let server_key = SecretKey::generate();
        let a_key = SecretKey::generate();
        let b_key = SecretKey::generate();

        // create tls_config
        let (tls_config, _) = make_tls_config();

        // start server
        let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(server_key))
            .tls_config(Some(tls_config))
            .spawn()
            .await?;

        let addr = server.addr();

        // get dial info & create region
        let port = addr.port();
        let addr = {
            if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
                ipv4_addr
            } else {
                anyhow::bail!("cannot get ipv4 addr from socket addr {addr:?}");
            }
        };
        println!("DERP listening on: {addr}:{port}");

        let region = DerpRegion {
            region_id: 1,
            avoid: false,
            nodes: vec![DerpNode {
                name: "test_node".to_string(),
                region_id: 1,
                url: format!("https://localhost:{port}").parse().unwrap(),
                stun_only: false,
                stun_port: 0,
                ipv4: UseIpv4::Some(addr),
                ipv6: UseIpv6::Disabled,
            }
            .into()],
            region_code: "test_region".to_string(),
        };

        // create clients
        let (a_key, mut a_recv, client_a_task, client_a) =
            create_test_client(a_key, region.clone(), None);
        println!("created client {a_key:?}");
        let (b_key, mut b_recv, client_b_task, client_b) = create_test_client(b_key, region, None);
        println!("created client {b_key:?}");

        client_a.ping().await?;
        client_b.ping().await?;

        println!("sending message from a to b");
        let msg = Bytes::from_static(b"hi there, client b!");
        client_a.send(b_key, msg.clone()).await?;
        println!("waiting for message from a on b");
        let (got_key, got_msg) = b_recv.recv().await.expect("expected message from client_a");
        assert_eq!(a_key, got_key);
        assert_eq!(msg, got_msg);

        println!("sending message from b to a");
        let msg = Bytes::from_static(b"right back at ya, client b!");
        client_b.send(a_key, msg.clone()).await?;
        println!("waiting for message b on a");
        let (got_key, got_msg) = a_recv.recv().await.expect("expected message from client_b");
        assert_eq!(b_key, got_key);
        assert_eq!(msg, got_msg);

        server.shutdown().await;
        client_a.close().await;
        client_a_task.abort();
        client_b.close().await;
        client_b_task.abort();
        Ok(())
    }
}
