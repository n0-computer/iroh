//! WebTransport server for the relay protocol.
//!
//! Accepts relay connections over QUIC/WebTransport, complementing the existing
//! WebSocket-over-HTTP/1.1 transport.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use n0_error::{AnyError, anyerr, e, stack_error};
use noq::crypto::rustls::{NoInitialCipherSuite, QuicServerConfig};
use tokio::task::JoinSet;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{Instrument, debug, info, info_span, trace, warn};
use web_transport_proto as wt;

use super::{
    client::Config, clients::Clients, http_server::RelayService, metrics::Metrics,
    streams::RelayedStream,
};
use crate::{
    KeyCache,
    http::{ALPN_RELAY_H3, CLIENT_AUTH_HEADER, ProtocolVersion, RELAY_PATH},
    protos::{h3_streams::WtBytesFramed, handshake},
    server::{ClientRequest, DynAccessControl},
};

/// Maximum time allowed for the WebTransport relay handshake, from an
/// established QUIC connection through to client registration.
///
/// Mirrors the WebSocket accept path's establish timeout: a peer that completes
/// the QUIC handshake but then never (or slowly) sends its SETTINGS or CONNECT
/// must not pin the connection and its drain tasks indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Streams that must stay open for the lifetime of a WebTransport relay session.
///
/// Dropping any of these resets the underlying QUIC stream, which a browser
/// treats as fatal: the HTTP/3 control stream is critical, and the WebTransport
/// session is bound to its CONNECT bidi stream, so closing either tears the
/// session down.
struct WtSessionStreams {
    _control: noq::SendStream,
    _connect_send: noq::SendStream,
    _connect_recv: noq::RecvStream,
}

/// Errors when spawning the H3 relay server.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum H3SpawnError {
    #[error(transparent)]
    NoInitialCipherSuite {
        #[error(std_err, from)]
        source: NoInitialCipherSuite,
    },
    #[error("Unable to spawn QUIC endpoint for H3 relay")]
    EndpointServer {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("Unable to get local address from H3 endpoint")]
    LocalAddr {
        #[error(std_err)]
        source: std::io::Error,
    },
}

/// A running H3/WebTransport relay server.
#[derive(Debug)]
pub struct H3RelayServer {
    bind_addr: SocketAddr,
    cancel: CancellationToken,
    handle: AbortOnDropHandle<()>,
}

impl H3RelayServer {
    /// Returns the bound socket address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Returns a handle for controlling this server.
    pub fn handle(&self) -> H3ServerHandle {
        H3ServerHandle {
            cancel: self.cancel.clone(),
        }
    }

    /// Returns a mutable reference to the task handle.
    pub(crate) fn task_handle(&mut self) -> &mut AbortOnDropHandle<()> {
        &mut self.handle
    }

    /// Spawns the H3/WebTransport relay server.
    ///
    /// The `service` is the same [`RelayService`] that backs the WebSocket server,
    /// so both transports register into one [`Clients`] registry and share the
    /// access control, key cache, and metrics. `bind_addr` and `server_config` are
    /// the QUIC-specific bind address and TLS configuration.
    pub(crate) fn spawn(
        bind_addr: SocketAddr,
        server_config: rustls::ServerConfig,
        service: RelayService,
    ) -> Result<Self, H3SpawnError> {
        let mut server_tls_config = server_config;
        server_tls_config.alpn_protocols = vec![ALPN_RELAY_H3.to_vec()];

        let quic_server_config = QuicServerConfig::try_from(server_tls_config)?;
        let mut server_config = noq::ServerConfig::with_crypto(Arc::new(quic_server_config));
        let transport_config = Arc::get_mut(&mut server_config.transport).expect("not used yet");
        // Uni streams: high limit for per-message uni streams.
        // Bidi streams: 1 for the CONNECT session.
        transport_config
            .max_concurrent_uni_streams(256u32.into())
            .max_concurrent_bidi_streams(2_u8.into());

        let endpoint = noq::Endpoint::server(server_config, bind_addr)
            .map_err(|err| e!(H3SpawnError::EndpointServer, err))?;
        let bind_addr = endpoint
            .local_addr()
            .map_err(|err| e!(H3SpawnError::LocalAddr, err))?;

        info!(?bind_addr, "H3/WT relay server listening");

        let cancel = CancellationToken::new();
        let cancel_loop = cancel.clone();

        let clients = service.clients().clone();
        let key_cache = service.key_cache().clone();
        let access = service.access().clone();
        let metrics = service.metrics().clone();

        let task = tokio::task::spawn(
            async move {
                let mut set = JoinSet::new();
                debug!("waiting for connections");
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel_loop.cancelled() => {
                            break;
                        }
                        Some(res) = set.join_next() => {
                            if let Err(err) = res
                                && err.is_panic()
                            {
                                panic!("H3/WT relay task panicked: {err:#?}");
                            }
                        }
                        res = endpoint.accept() => match res {
                            Some(incoming) => {
                                let remote_addr = incoming.remote_address();
                                debug!(%remote_addr, "accepting QUIC connection");
                                let clients = clients.clone();
                                let key_cache = key_cache.clone();
                                let metrics = metrics.clone();
                                let access = access.clone();
                                set.spawn(
                                    async move {
                                        if let Err(err) = handle_wt_connection(
                                            incoming, clients, key_cache, access, metrics,
                                        ).await {
                                            warn!("WT connection error: {err:#}");
                                        }
                                    }
                                    .instrument(info_span!("wt-relay-conn", %remote_addr))
                                );
                            }
                            None => {
                                debug!("endpoint closed");
                                break;
                            }
                        }
                    }
                }
                endpoint.close(0u32.into(), b"server shutdown");
                endpoint.wait_idle().await;
                set.abort_all();
                while !set.is_empty() {
                    _ = set.join_next().await;
                }
                debug!("H3/WT relay server shut down");
            }
            .instrument(info_span!("h3-wt-relay-serve")),
        );

        Ok(Self {
            bind_addr,
            cancel,
            handle: AbortOnDropHandle::new(task),
        })
    }

    /// Gracefully shuts down the server.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if !self.task_handle().is_finished() {
            _ = self.task_handle().await;
        }
    }
}

/// Handle for controlling the H3/WT relay server.
#[derive(Debug, Clone)]
pub struct H3ServerHandle {
    cancel: CancellationToken,
}

impl H3ServerHandle {
    /// Initiate graceful shutdown.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

/// Connection handling errors.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
enum WtConnectionError {
    #[error(transparent)]
    Quic {
        #[error(from, std_err)]
        source: noq::ConnectionError,
    },
    /// Error decoding the WebTransport settings sent by the client.
    ///
    /// The concrete error type is `web_transport_proto::SettingsError`. Use
    /// [`AnyError::downcast_ref`] to recover it. Note that the concrete downcast
    /// type is not covered by any semver guarantees and may change between releases.
    #[error("WebTransport settings error")]
    Settings { source: AnyError },
    /// Error encoding or decoding a WebTransport CONNECT message.
    ///
    /// The concrete error type is `web_transport_proto::ConnectError`. Use
    /// [`AnyError::downcast_ref`] to recover it. Note that the concrete downcast
    /// type is not covered by any semver guarantees and may change between releases.
    #[error("WebTransport CONNECT error")]
    Connect { source: AnyError },
    #[error(transparent)]
    Handshake {
        #[error(from, std_err)]
        source: handshake::Error,
    },
    #[error(transparent)]
    StreamWrite {
        #[error(from, std_err)]
        source: noq::WriteError,
    },
    #[error("invalid WebTransport CONNECT request")]
    Http {
        #[error(from, std_err)]
        source: http::Error,
    },
}

/// Read and discard the rest of a receive stream in a detached task, holding it
/// open until it finishes or the connection closes.
///
/// Used for the HTTP/3 control and QPACK unidirectional streams a real browser
/// opens: their contents are irrelevant to the relay, but resetting them (by
/// dropping the receive stream) would abort the browser's session.
fn drain_in_background<R>(mut reader: R)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::task::spawn(async move {
        let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
    });
}

/// Handle a single QUIC connection and serve WebTransport relay sessions.
async fn handle_wt_connection(
    incoming: noq::Incoming,
    clients: Clients,
    key_cache: KeyCache,
    access: Arc<dyn DynAccessControl>,
    metrics: Arc<Metrics>,
) -> Result<(), WtConnectionError> {
    let conn = incoming.await?;

    trace!("WT srv: QUIC connection established");

    // Bound the pre-registration handshake, mirroring the WebSocket accept path
    // (`ESTABLISH_TIMEOUT` in `http_server`): a peer that completes the QUIC
    // handshake but then never (or slowly) sends its SETTINGS/CONNECT must not
    // pin the connection and its drain tasks indefinitely.
    let session_streams = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        wt_relay_handshake(&conn, &clients, key_cache, access, metrics),
    )
    .await
    {
        Ok(res) => match res? {
            Some(streams) => streams,
            None => return Ok(()),
        },
        Err(_) => {
            warn!("WebTransport relay handshake timed out");
            return Ok(());
        }
    };

    // Hold the session's streams (HTTP/3 control stream and the CONNECT bidi
    // stream) open until the client disconnects; dropping them would reset the
    // streams and tear the WebTransport session down.
    let _session_streams = session_streams;
    conn.closed().await;

    Ok(())
}

/// Perform the WebTransport relay handshake and register the client.
///
/// Returns the server's HTTP/3 control send stream on success (the caller holds
/// it open for the connection's lifetime), or `None` if the handshake was
/// declined without error (client does not support WebTransport, wrong path, or
/// unsupported subprotocol). Runs under [`HANDSHAKE_TIMEOUT`].
async fn wt_relay_handshake(
    conn: &noq::Connection,
    clients: &Clients,
    key_cache: KeyCache,
    access: Arc<dyn DynAccessControl>,
    metrics: Arc<Metrics>,
) -> Result<Option<WtSessionStreams>, WtConnectionError> {
    let mut server_settings = wt::Settings::default();
    server_settings.enable_webtransport(1);

    let mut settings_buf = bytes::BytesMut::new();
    server_settings.encode(&mut settings_buf);

    let (send_result, recv_result) = tokio::join!(
        async {
            trace!("WT srv: sending settings");
            let mut uni = conn.open_uni().await?;
            uni.write_all(&settings_buf).await?;
            trace!("WT srv: settings sent");
            // Return the stream so the caller keeps it open: this is our HTTP/3
            // control stream, and a real browser aborts the connection with
            // H3_CLOSED_CRITICAL_STREAM if we reset it (which dropping would do).
            Ok::<_, WtConnectionError>(uni)
        },
        async {
            trace!("WT srv: waiting for client settings");
            // A native client opens exactly one uni stream (its H3 control
            // stream) before the CONNECT. A real browser additionally opens
            // QPACK encoder/decoder (and possibly GREASE) unidirectional
            // streams, in an unspecified order. Accept uni streams until we find
            // the control stream carrying the SETTINGS frame; drain and keep the
            // others alive so their (critical) streams are not reset.
            loop {
                let uni = conn.accept_uni().await?;
                let mut uni = tokio::io::BufReader::new(uni);
                match wt::Settings::read(&mut uni).await {
                    Ok(s) => {
                        trace!("WT srv: client settings received");
                        drain_in_background(uni);
                        break Ok::<_, WtConnectionError>(s);
                    }
                    Err(wt::SettingsError::UnexpectedStreamType(stream_type)) => {
                        trace!(?stream_type, "WT srv: ignoring non-control uni stream");
                        drain_in_background(uni);
                    }
                    Err(err) => break Err(e!(WtConnectionError::Settings, anyerr!(err))),
                }
            }
        }
    );
    // Keep our control stream open for the connection's lifetime.
    let control_send = send_result?;
    let client_settings = recv_result?;

    if client_settings.supports_webtransport() == 0 {
        warn!("client does not support WebTransport");
        return Ok(None);
    }

    trace!("WT srv: waiting for CONNECT");
    let (mut send, mut recv) = conn.accept_bi().await?;
    // Record the CONNECT stream's QUIC stream ID as the session ID.
    let session_id: u64 = send.id().into();
    let connect_req = wt::ConnectRequest::read(&mut recv)
        .await
        .map_err(|err| e!(WtConnectionError::Connect, anyerr!(err)))?;
    trace!(url = %connect_req.url, session_id, "WT srv: CONNECT received");

    if connect_req.url.path() != RELAY_PATH {
        warn!(path = %connect_req.url.path(), "invalid path, expected {RELAY_PATH}");
        let mut buf = bytes::BytesMut::new();
        let _ = wt::ConnectResponse::new(http::StatusCode::NOT_FOUND).encode(&mut buf);
        let _ = send.write_all(&buf).await;
        return Ok(None);
    }

    let protocol_version = if connect_req.protocols.is_empty() {
        // The browser's WebTransport CONNECT carries no subprotocol (the API has
        // no equivalent of a WebSocket subprotocol), so default to the latest
        // supported relay protocol version.
        ProtocolVersion::default()
    } else {
        match connect_req
            .protocols
            .iter()
            .filter_map(|s| ProtocolVersion::match_from_str(s.as_str()))
            .max()
        {
            Some(version) => version,
            None => {
                warn!("unsupported relay subprotocol");
                let mut buf = bytes::BytesMut::new();
                let _ = wt::ConnectResponse::new(http::StatusCode::BAD_REQUEST).encode(&mut buf);
                let _ = send.write_all(&buf).await;
                return Ok(None);
            }
        }
    };

    let client_auth_header = connect_req
        .headers
        .get(CLIENT_AUTH_HEADER.as_str())
        .cloned();

    let resp = wt::ConnectResponse::OK.with_protocol(protocol_version.to_string());
    let mut resp_buf = bytes::BytesMut::new();
    resp.encode(&mut resp_buf)
        .map_err(|err| e!(WtConnectionError::Connect, anyerr!(err)))?;
    trace!("WT srv: sending CONNECT response");
    send.write_all(&resp_buf).await?;

    // Use uni streams for relay messages (one stream per message).
    let mut io = WtBytesFramed::new(conn.clone(), session_id);

    trace!("WT srv: starting relay handshake");
    let authentication = handshake::serverside(&mut io, client_auth_header).await?;

    trace!(?authentication.mechanism, "verified authentication");

    // Build a `ClientRequest` from the WebTransport CONNECT request and authorize it
    // against the configured `AccessControl`, mirroring the WebSocket accept path.
    let request_parts = {
        let mut request = http::Request::builder()
            .uri(connect_req.url.as_str())
            .body(())?;
        *request.headers_mut() = connect_req.headers;
        request.into_parts().0
    };
    let request = ClientRequest::new(authentication.client_key, protocol_version, request_parts);
    let guard = authentication
        .authorize_with(&request, &access, &mut io)
        .await?;

    trace!("verified authorization");

    let io = RelayedStream::new(io, key_cache.clone());

    let endpoint_id = request.endpoint_id();
    let client_conn = Config::new(guard, io, protocol_version);

    trace!(endpoint_id = %endpoint_id.fmt_short(), "registering client");

    clients.register(client_conn, metrics.clone());

    debug!(endpoint_id = %endpoint_id.fmt_short(), "client registered");

    Ok(Some(WtSessionStreams {
        _control: control_send,
        _connect_send: send,
        _connect_recv: recv,
    }))
}
