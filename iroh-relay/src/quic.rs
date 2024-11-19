//! Create a QUIC server that accepts connections
//! for QUIC address discovery.
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;

use quinn::{ApplicationClose, VarInt};
use tokio::task::JoinSet;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, info, info_span, warn, Instrument};

use crate::server::QuicConfig;

/// ALPN for our quic addr discovery
pub const ALPN_QUIC_ADDR_DISC: &[u8] = b"quic";
/// Endpoint close error code
pub const QUIC_ADDR_DISC_CLOSE_CODE: VarInt = VarInt::from_u32(0);
/// Endpoint close reason
pub const QUIC_ADDR_DISC_CLOSE_REASON: &[u8] = b"finished";

pub(crate) struct QuicServer {
    bind_addr: SocketAddr,
    cancel: CancellationToken,
    handle: AbortOnDropHandle<()>,
}

impl QuicServer {
    /// Returns a handle for this server.
    ///
    /// The server runs in the background as several async tasks.  This allows controlling
    /// the server, in particular it allows gracefully shutting down the server.
    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            cancel_token: self.cancel.clone(),
        }
    }

    /// Returns the [`AbortOnDropHandle`] for the supervisor task managing the endpoint.
    ///
    /// This is the root of all the tasks for the QUIC address discovery service.  Aborting it will abort all the
    /// other tasks for the service.  Awaiting it will complete when all the service tasks are
    /// completed.[]
    pub fn task_handle(&mut self) -> &mut AbortOnDropHandle<()> {
        &mut self.handle
    }

    /// Returns the socket address for this QUIC server.
    pub fn bind_addr(&self) -> &SocketAddr {
        &self.bind_addr
    }

    /// Spawns a QUIC server that creates and QUIC endpoint and listens
    /// for QUIC connections for address discovery
    ///
    /// # Panics
    /// If there is a panic during a connection, it will be propigated
    /// up here. Any other errors in a connection will be logged as a
    ///  warning.
    pub(crate) async fn spawn(quic_config: QuicConfig) -> Result<Self> {
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(quic_config.server_config));
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config
            .max_concurrent_uni_streams(0_u8.into())
            // enable sending quic address discovery frames
            .send_observed_address_reports(true);

        let endpoint = quinn::Endpoint::server(server_config, quic_config.bind_addr)?;
        let bind_addr = endpoint.local_addr()?;

        let cancel = CancellationToken::new();
        let cancel_accept_loop = cancel.clone();

        let task = tokio::task::spawn(async move {
        let mut set = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = cancel_accept_loop.cancelled() => {
                    break;
                }
                Some(res) = set.join_next(), if !set.is_empty() => {
                    if let Err(err) = res {
                        if err.is_panic() {
                            panic!("task panicked: {:#?}", err);
                        }
                        warn!("connection failed: {err}");
                    }
                }
                res = endpoint.accept() => match res {
                    Some(conn) => {
                         debug!("accepting connection from {:?}", conn.remote_address())       ;
                         set.spawn(async move {
                             let remote_addr = conn.remote_address();
                             let res = handle_connection(conn).await;
                             if let Err(ref err) = res {
                                 warn!(remote_address = ?remote_addr, "error handling connection {err:?}")
                             }
                             res
                         });
                    }
                    None => {
                        debug!("endpoint closed");
                        break;
                    }
                }
            }
        }
        endpoint
            .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        endpoint.wait_idle().await;
        debug!("quic endpoint has been shutdown.");
        }.instrument(info_span!("quic-endpoint")),);
        Ok(Self {
            bind_addr,
            cancel,
            handle: AbortOnDropHandle::new(task),
        })
    }

    /// Closes the underlying QUIC endpoint and the tasks running the
    /// QUIC connections.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

/// A handle for the [`QuicServer`].
///
/// This does not allow access to the task but can communicate with it.
#[derive(Debug, Clone)]
pub struct ServerHandle {
    cancel_token: CancellationToken,
}

impl ServerHandle {
    /// Gracefully shut down the quic endpoint.
    pub fn shutdown(&self) {
        self.cancel_token.cancel()
    }
}

async fn handle_connection(conn: quinn::Incoming) -> Result<()> {
    let connection = conn.await?;
    // let span = info_span!(
    //     "connection",
    //     remote = %connection.remote_address(),
    //     protocol = %connection
    //         .handshake_data()
    //         .unwrap()
    //         .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
    //         .protocol
    //         .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    // );
    info!("established");
    // wait for the client to close the connection
    let connection_err = connection.closed().await;
    match connection_err {
        quinn::ConnectionError::ApplicationClosed(ApplicationClose { error_code, .. })
            if error_code == QUIC_ADDR_DISC_CLOSE_CODE =>
        {
            return Ok(());
        }
        _ => {
            warn!(
                "{} - error closing connection {connection_err:?}",
                connection.remote_address()
            );
        }
    }
    Ok(())
}

/// Client side function to correctly handle QUIC address discovery
///
/// Consumes and gracefully closes the connection, even when cancelled early.
pub async fn get_observed_address_from_conn(
    conn: quinn::Connection,
    cancel: CancellationToken,
) -> Result<SocketAddr> {
    let mut external_addresses = conn.observed_external_addr();
    tokio::select! {
        _ = cancel.cancelled() => {
            conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
            anyhow::bail!("QUIC address discovery canceled early");
        },
        res = external_addresses.wait_for(|addr| addr.is_some()) => {
            let addr = res?.expect("checked");
            // gracefully close the connections
            conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
            Ok(addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use super::*;

    /// Create certs and rustls::ServerConfig for local use
    ///
    /// The certificate covers the domain "localhost".
    fn generate_self_signed_localhost_config(
        cert: rustls::pki_types::CertificateDer<'static>,
        private_key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::ServerConfig,
    )> {
        let rustls_certs = vec![cert];
        let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocols supported by ring")
        .with_no_client_auth()
        .with_single_cert(rustls_certs.clone(), private_key)?;
        Ok((rustls_certs, server_config))
    }

    fn generate_certs_and_priv_key() -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("valid");
        let private_key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.get_key_pair().serialize_der());
        let private_key = rustls::pki_types::PrivateKeyDer::from(private_key);
        let cert = rustls::pki_types::CertificateDer::from(cert.serialize_der().unwrap());
        (cert, private_key)
    }

    /// Generates a [`quinn::ClientConfig`] that has quic address discovery enabled.
    fn generate_quic_addr_disc_client_config(
        cert: rustls::pki_types::CertificateDer<'static>,
    ) -> Result<quinn::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert)?;
        let mut config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![ALPN_QUIC_ADDR_DISC.into()];
        let config = quinn_proto::crypto::rustls::QuicClientConfig::try_from(config).unwrap();
        let mut transport = quinn_proto::TransportConfig::default();
        // enable address discovery
        transport
            .send_observed_address_reports(true)
            .receive_observed_address_reports(true);

        let mut client_config = quinn::ClientConfig::new(Arc::new(config));
        client_config.transport_config(Arc::new(transport));
        Ok(client_config)
    }

    #[tokio::test]
    async fn quic_endpoint_basic() -> anyhow::Result<()> {
        let localhost: Ipv4Addr = "127.0.0.1".parse()?;
        let _guard = iroh_test::logging::setup();
        let (cert, private_key) = generate_certs_and_priv_key();
        let client_cert = cert.clone();

        let (_, server_config) = generate_self_signed_localhost_config(cert, private_key)?;

        let quic_server = QuicServer::spawn(QuicConfig::new(
            server_config,
            localhost.clone().into(),
            Some(0),
        )?)
        .await?;

        let client_config = generate_quic_addr_disc_client_config(client_cert)?;
        let mut client_endpoint = quinn::Endpoint::client(SocketAddr::new(localhost.into(), 0))?;
        client_endpoint.set_default_client_config(client_config);

        let client_addr = client_endpoint.local_addr()?;
        println!("{client_addr}");

        let conn = client_endpoint
            .connect(quic_server.bind_addr.clone(), "localhost")?
            .await?;

        let addr = get_observed_address_from_conn(conn, CancellationToken::new()).await?;
        // wait until the endpoint delivers the closing message to the server
        client_endpoint.wait_idle().await;
        // shut down the quic server
        quic_server.shutdown();

        assert_eq!(client_addr, addr);
        Ok(())
    }
}
