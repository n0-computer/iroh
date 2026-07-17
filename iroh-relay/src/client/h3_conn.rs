//! WebTransport client connection for the relay protocol.
//!
//! This is the QUIC/WebTransport counterpart to the WebSocket transport in the
//! parent [`client`](super) module. Both speak the same relay protocol and share
//! the same [`handshake`], so a WebTransport client can relay to a WebSocket peer
//! and vice versa. WebTransport reaches the first relay byte in ~2 RTTs where
//! WebSocket needs 3-4 (TCP + TLS + HTTP upgrade + relay auth).
//!
//! Connecting happens in two phases so the [`ClientBuilder`] can race the QUIC
//! handshake against a WebSocket connect and keep whichever wins:
//!
//! 1. [`quic_connect`] performs the QUIC handshake (1 RTT, TLS 1.3 included). The
//!    [`ClientBuilder`] runs this Happy Eyeballs style across the resolved relay
//!    addresses, the same way the WebSocket path dials.
//! 2. [`wt_handshake`] completes the WebTransport session on the established
//!    connection. Per RFC 9114 section 7.2.4.2 it does not wait for the peer's
//!    settings before sending: client `SETTINGS` (on a uni stream) and the
//!    WebTransport `CONNECT` request (on a bidi stream) go out in the first
//!    flight while the server's `SETTINGS` are read concurrently. The `CONNECT`
//!    carries the relay subprotocol and, when the connection exports keying
//!    material, an RFC 5705 auth header so the relay [`handshake`] adds no extra
//!    RTT. Once the server accepts, relay messages flow over [`WtBytesFramed`],
//!    one QUIC uni stream per message.
//!
//! If the server does not speak WebTransport (its settings disable it, or the
//! `CONNECT` is rejected) the caller falls back to WebSocket.
//!
//! [`ClientBuilder`]: super::ClientBuilder
//! [`handshake`]: crate::protos::handshake

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use iroh_base::SecretKey;
use n0_error::{AnyError, anyerr, e, stack_error};
use noq::crypto::rustls::QuicClientConfig;
use tracing::{debug, trace};
use web_transport_proto as wt;

use crate::{
    http::{ALPN_RELAY_H3, CLIENT_AUTH_HEADER, ProtocolVersion, RELAY_PATH},
    protos::{
        h3_streams::WtBytesFramed,
        handshake::{self, KeyMaterialClientAuth},
    },
};

/// Timeout for the QUIC handshake when connecting via WebTransport.
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// WebTransport connection state that must outlive the relay stream.
///
/// Dropping this closes the QUIC connection.
pub(crate) struct WtConnState {
    _conn: noq::Connection,
}

/// Errors during WebTransport relay connection establishment.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum H3ConnectError {
    #[error(transparent)]
    QuicConnect {
        #[error(from, std_err)]
        source: noq::ConnectError,
    },
    #[error(transparent)]
    QuicConnection {
        #[error(from, std_err)]
        source: noq::ConnectionError,
    },
    /// Error decoding the WebTransport settings sent by the server.
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
    /// The server does not support WebTransport.
    #[error("Server does not support WebTransport")]
    WebTransportUnsupported {},
    #[error("Server rejected session: {status}")]
    Rejected { status: http::StatusCode },
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
    #[error("No local address available")]
    NoLocalAddr {},
    #[error(transparent)]
    EndpointCreate {
        #[error(from, std_err)]
        source: std::io::Error,
    },
    #[error("QUIC connect timed out")]
    ConnectTimeout {},
}

/// Result of the QUIC connect phase. Passed to [`wt_handshake`] to complete
/// the WebTransport session setup.
pub(crate) struct QuicConnected {
    pub conn: noq::Connection,
    pub local_addr: SocketAddr,
}

/// Phase 1: establish a QUIC connection (first server response).
///
/// Returns as soon as the QUIC handshake completes, confirming the server
/// speaks QUIC on this port. This is the earliest signal for the WS/WT race.
pub(crate) async fn quic_connect(
    server_addr: SocketAddr,
    server_name: &str,
    tls_config: rustls::ClientConfig,
) -> Result<QuicConnected, H3ConnectError> {
    let bind_addr = if server_addr.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };

    let endpoint = noq::Endpoint::client(bind_addr)?;
    let local_addr = endpoint
        .local_addr()
        .map_err(|_| e!(H3ConnectError::NoLocalAddr))?;

    let mut tls_config = tls_config;
    tls_config.alpn_protocols = vec![ALPN_RELAY_H3.to_vec()];
    let quic_client_config = QuicClientConfig::try_from(tls_config).map_err(|_| {
        e!(H3ConnectError::EndpointCreate {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS config does not support TLS 1.3 (required for QUIC)",
            )
        })
    })?;
    let mut client_config = noq::ClientConfig::new(Arc::new(quic_client_config));
    let mut transport = noq_proto::TransportConfig::default();
    transport.max_concurrent_uni_streams(256u32.into());
    client_config.transport_config(Arc::new(transport));

    trace!(%server_addr, %server_name, "WT: QUIC connecting");
    let connecting = endpoint.connect_with(client_config, server_addr, server_name)?;
    let conn = tokio::time::timeout(QUIC_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| e!(H3ConnectError::ConnectTimeout))??;

    trace!("WT: QUIC handshake complete");
    Ok(QuicConnected { conn, local_addr })
}

/// Phase 2: complete the WebTransport handshake on an established QUIC connection.
///
/// Sends settings + CONNECT, receives server response, sets up the data stream,
/// and runs the relay handshake.
pub(crate) async fn wt_handshake(
    quic: QuicConnected,
    server_name: &str,
    secret_key: &SecretKey,
) -> Result<(WtBytesFramed, WtConnState, SocketAddr), H3ConnectError> {
    let QuicConnected { conn, local_addr } = quic;

    // Per RFC 9114 section 7.2.4.2, endpoints must not wait for peer settings
    // before sending. We pipeline settings + CONNECT in the first flight and
    // accept server settings concurrently. If the server does not support
    // WebTransport, the CONNECT will be rejected and we fall back to WS.
    let mut client_settings = wt::Settings::default();
    client_settings.enable_webtransport(1);

    // Build CONNECT request with relay subprotocol and auth header.
    let url = format!("https://{server_name}{RELAY_PATH}");
    let mut connect_req = wt::ConnectRequest::new(url::Url::parse(&url).expect("valid URL"))
        .with_protocol(ProtocolVersion::default().to_string());

    // Attach TLS keying material auth to avoid the challenge-response RTT.
    if let Some(client_auth) = KeyMaterialClientAuth::new(secret_key, &conn) {
        debug!("using TLS keying material for relay authentication");
        connect_req = connect_req.with_header(CLIENT_AUTH_HEADER, client_auth.into_header_value());
    }

    // Pre-encode settings and CONNECT into byte buffers.
    let mut settings_buf = bytes::BytesMut::new();
    client_settings.encode(&mut settings_buf);

    let mut connect_buf = bytes::BytesMut::new();
    connect_req
        .encode(&mut connect_buf)
        .map_err(|err| e!(H3ConnectError::Connect, anyerr!(err)))?;

    // Send settings and CONNECT in the same flight.
    let send_all = async {
        trace!("WT: opening uni stream for settings");
        let mut uni = conn.open_uni().await?;
        uni.write_all(&settings_buf).await?;
        trace!("WT: settings written");

        trace!("WT: opening bidi stream for CONNECT");
        let (mut connect_send, connect_recv) = conn.open_bi().await?;
        let session_id: u64 = connect_send.id().into();
        connect_send.write_all(&connect_buf).await?;
        trace!("WT: CONNECT written");

        Ok::<_, H3ConnectError>((connect_recv, session_id))
    };

    let settings_recv = async {
        trace!("WT: waiting for server settings");
        let uni = conn.accept_uni().await?;
        let mut uni = tokio::io::BufReader::new(uni);
        let settings = wt::Settings::read(&mut uni)
            .await
            .map_err(|err| e!(H3ConnectError::Settings, anyerr!(err)))?;
        trace!("WT: server settings received");
        Ok::<_, H3ConnectError>(settings)
    };

    let (send_result, server_settings) = tokio::join!(send_all, settings_recv);
    let (mut recv, session_id) = send_result?;
    let server_settings = server_settings?;

    if server_settings.supports_webtransport() == 0 {
        return Err(e!(H3ConnectError::WebTransportUnsupported));
    }

    trace!("WT: pipelined, waiting for CONNECT response");

    let resp = wt::ConnectResponse::read(&mut recv)
        .await
        .map_err(|err| e!(H3ConnectError::Connect, anyerr!(err)))?;

    trace!(status = %resp.status, "WT: CONNECT response received");

    if !resp.status.is_success() {
        return Err(e!(H3ConnectError::Rejected {
            status: resp.status,
        }));
    }

    // Use uni streams for relay messages (one stream per message).
    let mut io = WtBytesFramed::new(conn.clone(), session_id);

    trace!("WT: starting relay handshake");
    handshake::clientside(&mut io, secret_key).await?;
    trace!("WT: relay handshake complete");

    let state = WtConnState { _conn: conn };

    Ok((io, state, local_addr))
}

/// Convenience: run both phases in sequence. Used in tests.
#[cfg(test)]
pub(crate) async fn connect_h3(
    server_addr: SocketAddr,
    server_name: &str,
    tls_config: rustls::ClientConfig,
    secret_key: &SecretKey,
) -> Result<(WtBytesFramed, WtConnState, SocketAddr), H3ConnectError> {
    let quic = quic_connect(server_addr, server_name, tls_config).await?;
    wt_handshake(quic, server_name, secret_key).await
}
