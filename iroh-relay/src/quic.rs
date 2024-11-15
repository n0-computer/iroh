//! Create a QUIC server that accepts connections
//! for QUIC address discovery.
use std::sync::Arc;

use anyhow::Result;

use quinn::VarInt;
use tokio::task::JoinSet;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, error, info, info_span, warn, Instrument};

use crate::server::QuicConfig;

/// ALPN for our quic addr discovery
pub const ALPN_QUIC_ADDR_DISC: &[u8] = b"quic";
/// Endpoint close error code
pub const QUIC_ADDR_DISC_CLOSE_CODE: VarInt = VarInt::from_u32(0);
/// Endpoint close reason
pub const QUIC_ADDR_DISC_CLOSE_REASON: &[u8] = b"finished";

pub(crate) struct QuicServer {
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
        transport_config.max_concurrent_uni_streams(0_u8.into());

        let endpoint = quinn::Endpoint::server(server_config, quic_config.bind_addr)?;

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
                             handle_connection(conn)
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
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            let fut = handle_request(stream);
            tokio::spawn(
                async move {
                    if let Err(e) = fut.await {
                        error!("failed: {reason}", reason = e.to_string());
                    }
                }
                .instrument(info_span!("request")),
            );
        }
    }
    .instrument(span)
    .await?;
    Ok(())
}

async fn handle_request(
    (mut send, mut _recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let resp = b"test";
    send.write_all(resp)
        .await
        .map_err(|e| anyhow::anyhow!("failed to send response: {}", e))?;
    // Gracefully terminate the stream
    send.finish()
        .map_err(|e| anyhow::anyhow!("failed to shutdown stream: {}", e))?;
    info!("complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn quic_endpoint_basic() -> anyhow::Result<()> {
        let _guard = iroh_test::logging::setup();

        let _key = iroh_base::key::SecretKey::generate();
        // create cert from key
        // start up server on localhost
        // start up client conn
        // connect to server ep
        // wait for addr
        todo!();
    }
}
