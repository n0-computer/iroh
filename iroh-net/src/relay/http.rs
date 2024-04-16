//! An http specific relay Client and relay Server. Allows for using tls or non tls connection
//! upgrades.
//!
mod client;
mod server;

pub use self::client::{Client, ClientBuilder, ClientError, ClientReceiver};
pub use self::server::{Server, ServerBuilder, TlsAcceptor, TlsConfig};

pub(crate) const HTTP_UPGRADE_PROTOCOL: &str = "iroh derp http";

#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn make_tls_config() -> TlsConfig {
    let subject_alt_names = vec!["localhost".to_string()];

    let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
    let rustls_certificate = rustls::Certificate(cert.serialize_der().unwrap());
    let rustls_key = rustls::PrivateKey(cert.get_key_pair().serialize_der());
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![(rustls_certificate)], rustls_key)
        .unwrap();

    let config = std::sync::Arc::new(config);
    let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());

    TlsConfig {
        config,
        acceptor: TlsAcceptor::Manual(acceptor),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use bytes::Bytes;
    use reqwest::Url;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tracing::{info, info_span, Instrument};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use crate::key::{PublicKey, SecretKey};
    use crate::relay::ReceivedMessage;

    #[tokio::test]
    async fn test_http_clients_and_server() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let server_key = SecretKey::generate();
        let a_key = SecretKey::generate();
        let b_key = SecretKey::generate();

        // start server
        let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(server_key))
            .spawn()
            .await?;

        let addr = server.addr();

        // get dial info
        let port = addr.port();
        let addr = {
            if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
                ipv4_addr
            } else {
                anyhow::bail!("cannot get ipv4 addr from socket addr {addr:?}");
            }
        };
        info!("addr: {addr}:{port}");
        let relay_addr: Url = format!("http://{addr}:{port}").parse().unwrap();

        // create clients
        let (a_key, mut a_recv, client_a_task, client_a) = {
            let span = info_span!("client-a");
            let _guard = span.enter();
            create_test_client(a_key, relay_addr.clone())
        };
        info!("created client {a_key:?}");
        let (b_key, mut b_recv, client_b_task, client_b) = {
            let span = info_span!("client-b");
            let _guard = span.enter();
            create_test_client(b_key, relay_addr)
        };
        info!("created client {b_key:?}");

        info!("ping a");
        client_a.ping().await?;

        info!("ping b");
        client_b.ping().await?;

        info!("sending message from a to b");
        let msg = Bytes::from_static(b"hi there, client b!");
        client_a.send(b_key, msg.clone()).await?;
        info!("waiting for message from a on b");
        let (got_key, got_msg) = b_recv.recv().await.expect("expected message from client_a");
        assert_eq!(a_key, got_key);
        assert_eq!(msg, got_msg);

        info!("sending message from b to a");
        let msg = Bytes::from_static(b"right back at ya, client b!");
        client_b.send(a_key, msg.clone()).await?;
        info!("waiting for message b on a");
        let (got_key, got_msg) = a_recv.recv().await.expect("expected message from client_b");
        assert_eq!(b_key, got_key);
        assert_eq!(msg, got_msg);

        client_a.close().await?;
        client_a_task.abort();
        client_b.close().await?;
        client_b_task.abort();
        server.shutdown().await;

        Ok(())
    }

    fn create_test_client(
        key: SecretKey,
        server_url: Url,
    ) -> (
        PublicKey,
        mpsc::Receiver<(PublicKey, Bytes)>,
        JoinHandle<()>,
        Client,
    ) {
        let client = ClientBuilder::new(server_url).insecure_skip_cert_verify(true);
        let dns_resolver = crate::dns::default_resolver();
        let (client, mut client_reader) = client.build(key.clone(), dns_resolver.clone());
        let public_key = key.public();
        let (received_msg_s, received_msg_r) = tokio::sync::mpsc::channel(10);
        let client_reader_task = tokio::spawn(
            async move {
                loop {
                    info!("waiting for message on {:?}", key.public());
                    match client_reader.recv().await {
                        None => {
                            info!("client received nothing");
                            return;
                        }
                        Some(Err(e)) => {
                            info!("client {:?} `recv` error {e}", key.public());
                            return;
                        }
                        Some(Ok((msg, _))) => {
                            info!("got message on {:?}: {msg:?}", key.public());
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
            .instrument(info_span!("test-client-reader")),
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
        let tls_config = make_tls_config();

        // start server
        let server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(server_key))
            .tls_config(Some(tls_config))
            .spawn()
            .await?;

        let addr = server.addr();

        // get dial info
        let port = addr.port();
        let addr = {
            if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
                ipv4_addr
            } else {
                anyhow::bail!("cannot get ipv4 addr from socket addr {addr:?}");
            }
        };
        info!("Relay listening on: {addr}:{port}");

        let url: Url = format!("https://localhost:{port}").parse().unwrap();

        // create clients
        let (a_key, mut a_recv, client_a_task, client_a) = create_test_client(a_key, url.clone());
        info!("created client {a_key:?}");
        let (b_key, mut b_recv, client_b_task, client_b) = create_test_client(b_key, url);
        info!("created client {b_key:?}");

        client_a.ping().await?;
        client_b.ping().await?;

        info!("sending message from a to b");
        let msg = Bytes::from_static(b"hi there, client b!");
        client_a.send(b_key, msg.clone()).await?;
        info!("waiting for message from a on b");
        let (got_key, got_msg) = b_recv.recv().await.expect("expected message from client_a");
        assert_eq!(a_key, got_key);
        assert_eq!(msg, got_msg);

        info!("sending message from b to a");
        let msg = Bytes::from_static(b"right back at ya, client b!");
        client_b.send(a_key, msg.clone()).await?;
        info!("waiting for message b on a");
        let (got_key, got_msg) = a_recv.recv().await.expect("expected message from client_b");
        assert_eq!(b_key, got_key);
        assert_eq!(msg, got_msg);

        server.shutdown().await;
        client_a.close().await?;
        client_a_task.abort();
        client_b.close().await?;
        client_b_task.abort();
        Ok(())
    }
}
