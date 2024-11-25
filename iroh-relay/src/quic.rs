//! Create a QUIC server that accepts connections
//! for QUIC address discovery.
use std::{net::SocketAddr, sync::Arc};

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
    /// If there is a panic during a connection, it will be propagated
    /// up here. Any other errors in a connection will be logged as a
    ///  warning.
    pub(crate) fn spawn(quic_config: QuicConfig) -> Result<Self> {
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(quic_config.server_config));
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config
            .max_concurrent_uni_streams(0_u8.into())
            // enable sending quic address discovery frames
            .send_observed_address_reports(true);

        let endpoint = quinn::Endpoint::server(server_config, quic_config.bind_addr)?;
        let bind_addr = endpoint.local_addr()?;

        info!("QUIC server bound on {bind_addr:?}");

        let cancel = CancellationToken::new();
        let cancel_accept_loop = cancel.clone();

        let task = tokio::task::spawn(async move {
            let mut set = JoinSet::new();
            debug!("waiting for connections...");
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

/// A handle for the Server side of QUIC address discovery.
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

/// Handles the client side of QUIC address discovery.
#[derive(Debug)]
pub struct QuicClient {
    /// A QUIC Endpoint.
    ep: quinn::Endpoint,
    /// A client config.
    client_config: quinn::ClientConfig,
}

impl QuicClient {
    /// Create a new QuicClient to handle the client side of QUIC
    /// address discovery.
    pub fn new(ep: quinn::Endpoint, mut client_config: quinn::ClientConfig) -> Self {
        let mut transport = quinn_proto::TransportConfig::default();
        // enable address discovery
        transport
            .send_observed_address_reports(true)
            .receive_observed_address_reports(true);
        client_config.transport_config(Arc::new(transport));
        Self { ep, client_config }
    }

    /// Client side of QUIC address discovery.
    ///
    /// Creates a connection and returns the observed address
    /// and estimated latency of the connection.
    ///
    /// Consumes and gracefully closes the connection.
    pub async fn get_addr_and_latency(
        &self,
        server_addr: SocketAddr,
        host: &str,
    ) -> Result<(SocketAddr, std::time::Duration)> {
        let connecting = self
            .ep
            .connect_with(self.client_config.clone(), server_addr, host);
        let conn = connecting?.await?;
        let mut external_addresses = conn.observed_external_addr();
        // TODO(ramfox): I'd like to be able to cancel this so we can close cleanly
        // if there the task that runs this function gets aborted.
        // tokio::select! {
        //     _ = cancel.cancelled() => {
        //         conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        //         anyhow::bail!("QUIC address discovery canceled early");
        //     },
        //     res = external_addresses.wait_for(|addr| addr.is_some()) => {
        //         let addr = res?.expect("checked");
        //         let latency = conn.rtt() / 2;
        //         // gracefully close the connections
        //         conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        //         Ok((addr, latency))
        //     }

        let res = match external_addresses.wait_for(|addr| addr.is_some()).await {
            Ok(res) => res,
            Err(err) => {
                // attempt to gracefully close the connections
                conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
                return Err(err.into());
            }
        };
        let mut observed_addr = res.expect("checked");
        // if we've sent an to an ipv4 address, but
        // received an observed address that is ivp6
        // then the address is an [IPv4-Mapped IPv6 Addresses](https://doc.rust-lang.org/beta/std/net/struct.Ipv6Addr.html#ipv4-mapped-ipv6-addresses)
        if server_addr.is_ipv4() && observed_addr.is_ipv6() {
            observed_addr =
                SocketAddr::new(observed_addr.ip().to_canonical(), observed_addr.port());
        }
        let latency = conn.rtt() / 2;
        // gracefully close the connections
        conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        Ok((observed_addr, latency))
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use super::*;

    /// Generates a [`quinn::ClientConfig`] that has quic address discovery enabled.
    fn generate_quic_addr_disc_client_config(
        cert: rustls::pki_types::CertificateDer<'static>,
    ) -> Result<quinn::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert)?;
        let config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        let config = quinn_proto::crypto::rustls::QuicClientConfig::try_from(config).unwrap();

        let client_config = quinn::ClientConfig::new(Arc::new(config));
        Ok(client_config)
    }

    #[tokio::test]
    async fn quic_endpoint_basic() -> anyhow::Result<()> {
        let host: Ipv4Addr = "127.0.0.1".parse()?;
        let _guard = iroh_test::logging::setup();

        let (certs, server_config) =
            super::super::server::testing::self_signed_tls_certs_and_config();

        let quic_server = QuicServer::spawn(QuicConfig::new(
            server_config,
            host.clone().into(),
            Some(0),
        )?)?;

        let client_config = generate_quic_addr_disc_client_config(certs[0].clone())?;
        let client_endpoint = quinn::Endpoint::client(SocketAddr::new(host.into(), 0))?;

        let client_addr = client_endpoint.local_addr()?;
        println!("{client_addr}");
        let quic_client = QuicClient::new(client_endpoint.clone(), client_config);

        let (addr, _latency) = quic_client
            .get_addr_and_latency(quic_server.bind_addr.clone(), &host.to_string())
            .await?;
        // wait until the endpoint delivers the closing message to the server
        client_endpoint.wait_idle().await;
        // shut down the quic server
        quic_server.shutdown();

        assert_eq!(client_addr, addr);
        Ok(())
    }
}
