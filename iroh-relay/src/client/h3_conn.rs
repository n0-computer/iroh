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
//!    framed per the negotiated `H3Opts::transfer_mode` (one uni stream per
//!    message, one datagram per message, or a single ordered uni stream).
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

use bytes::BytesMut;
use iroh_base::SecretKey;
use n0_error::{AnyError, anyerr, e, stack_error};
use noq::crypto::rustls::QuicClientConfig;
use tracing::{debug, trace};
use url::Url;
use web_transport_proto as wt;

use crate::{
    http::{
        ALPN_RELAY_H3, CLIENT_AUTH_HEADER, ProtocolVersion, RELAY_PATH, RELAY_WT_MODE_QUERY_PARAM,
    },
    protos::{
        h3_streams::{H3_MIN_MTU, MAX_CONCURRENT_UNI_STREAMS, WtBytesFramed},
        handshake::{self, KeyMaterialClientAuth},
    },
    relay_map::WtTransferMode,
};

/// Timeout for the QUIC handshake when connecting via WebTransport.
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for the WebTransport handshake once the QUIC connection is up.
///
/// Bounds phase 2 (settings exchange, CONNECT, and the relay handshake). Without
/// it a server that completes the QUIC handshake and then stalls would hang the
/// whole connect: because QUIC wins the transport race, the WebSocket fallback is
/// only reached once this handshake fails.
const WT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// WebTransport connection state that must outlive the relay stream.
///
/// Dropping this closes the QUIC connection.
pub(crate) struct WtConnState {
    _conn: noq::Connection,
    /// The client endpoint the connection was opened on. noq keeps a connection
    /// alive as long as any `Connection` handle exists (its endpoint driver runs
    /// while the endpoint has live connections, even after every `Endpoint`
    /// handle is dropped), so holding the endpoint here is not strictly required
    /// -- but retaining it for the connection's whole lifetime removes any doubt
    /// that a stray endpoint drop could close the connection with error code 0.
    _endpoint: noq::Endpoint,
}

/// Errors during WebTransport relay connection establishment.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum H3ConnectError {
    #[error("Invalid server URL")]
    InvalidServerUrl {
        #[error(from, std_err)]
        source: url::ParseError,
    },
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
    #[error("WebTransport handshake timed out")]
    HandshakeTimeout {},
}

/// Result of the QUIC connect phase. Passed to [`wt_handshake`] to complete
/// the WebTransport session setup.
pub(super) struct QuicConnected {
    pub(super) conn: noq::Connection,
    pub(super) local_addr: SocketAddr,
    pub(super) _endpoint: noq::Endpoint,
}

/// Phase 1: establish a QUIC connection (first server response).
///
/// Returns as soon as the QUIC handshake completes, confirming the server
/// speaks QUIC on this port. This is the earliest signal for the WS/WT race.
pub(super) async fn quic_connect(
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
    transport.max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into());
    // Keep the datagram budget above iroh's 1200-byte QUIC packet floor for the
    // whole connection -- both before MTU discovery runs and after a black-hole
    // reset; see [`H3_MIN_MTU`].
    transport.min_mtu(H3_MIN_MTU).initial_mtu(H3_MIN_MTU);
    client_config.transport_config(Arc::new(transport));

    trace!(%server_addr, %server_name, "WT: QUIC connecting");
    let connecting = endpoint.connect_with(client_config, server_addr, server_name)?;
    let conn = tokio::time::timeout(QUIC_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| e!(H3ConnectError::ConnectTimeout))??;

    trace!("WT: QUIC handshake complete");
    Ok(QuicConnected {
        conn,
        local_addr,
        _endpoint: endpoint,
    })
}

/// Phase 2: complete the WebTransport handshake on an established QUIC connection.
///
/// Sends settings + CONNECT, receives server response, sets up the data stream,
/// and runs the relay handshake. Bounded by [`WT_HANDSHAKE_TIMEOUT`].
pub(super) async fn wt_handshake(
    quic: QuicConnected,
    server_name: &str,
    secret_key: &SecretKey,
    transfer_mode: WtTransferMode,
) -> Result<(WtBytesFramed, WtConnState, SocketAddr), H3ConnectError> {
    tokio::time::timeout(
        WT_HANDSHAKE_TIMEOUT,
        wt_handshake_inner(quic, server_name, secret_key, transfer_mode),
    )
    .await
    .map_err(|_| e!(H3ConnectError::HandshakeTimeout))?
}

async fn wt_handshake_inner(
    quic: QuicConnected,
    server_name: &str,
    secret_key: &SecretKey,
    transfer_mode: WtTransferMode,
) -> Result<(WtBytesFramed, WtConnState, SocketAddr), H3ConnectError> {
    let QuicConnected {
        conn,
        local_addr,
        _endpoint,
    } = quic;

    // Per RFC 9114 section 7.2.4.2, endpoints must not wait for peer settings
    // before sending. We pipeline settings + CONNECT in the first flight and
    // accept server settings concurrently. If the server does not support
    // WebTransport, the CONNECT will be rejected and we fall back to WS.
    let mut client_settings = wt::Settings::default();
    client_settings.enable_webtransport(1);

    // Build CONNECT request with relay subprotocol and auth header. Select the
    // framing mode via a URL query parameter (rather than a header) so client and
    // server share one negotiation mechanism with the browser, whose WebTransport
    // CONNECT cannot carry custom headers.
    let mut url: Url = format!("https://{server_name}{RELAY_PATH}").parse()?;
    url.query_pairs_mut()
        .append_pair(RELAY_WT_MODE_QUERY_PARAM, transfer_mode.query_value());
    let mut connect_req =
        wt::ConnectRequest::new(url).with_protocol(ProtocolVersion::default().to_string());

    // Attach TLS keying material auth to avoid the challenge-response RTT.
    if let Some(client_auth) = KeyMaterialClientAuth::new(secret_key, &conn) {
        debug!("using TLS keying material for relay authentication");
        connect_req = connect_req.with_header(CLIENT_AUTH_HEADER, client_auth.into_header_value());
    }

    let send_settings = async {
        let mut buf = BytesMut::new();
        client_settings.encode(&mut buf);
        trace!("WT: opening uni stream for settings");
        let mut uni = conn.open_uni().await?;
        uni.write_chunk(buf.freeze()).await?;
        trace!("WT: settings written");
        Ok::<_, H3ConnectError>(())
    };

    let send_connect = async {
        let mut buf = BytesMut::new();
        connect_req
            .encode(&mut buf)
            .map_err(|err| e!(H3ConnectError::Connect, anyerr!(err)))?;
        trace!("WT: opening bidi stream for CONNECT");
        let (mut connect_send, connect_recv) = conn.open_bi().await?;
        let session_id: u64 = connect_send.id().into();
        connect_send.write_chunk(buf.freeze()).await?;
        trace!("WT: CONNECT written");
        Ok((connect_recv, session_id))
    };

    let recv_settings = async {
        trace!("WT: waiting for server settings");
        let uni = conn.accept_uni().await?;
        let mut uni = tokio::io::BufReader::new(uni);
        let settings = wt::Settings::read(&mut uni)
            .await
            .map_err(|err| e!(H3ConnectError::Settings, anyerr!(err)))?;
        trace!("WT: server settings received");
        Ok::<_, H3ConnectError>(settings)
    };

    // Run the 3 futures concurrently, aborting on any error.
    let ((), (mut connect_recv, session_id), server_settings) =
        tokio::try_join!(send_settings, send_connect, recv_settings)?;

    if server_settings.supports_webtransport() == 0 {
        return Err(e!(H3ConnectError::WebTransportUnsupported));
    }

    trace!("WT: remote supports WebTransports, waiting for CONNECT response");

    let resp = wt::ConnectResponse::read(&mut connect_recv)
        .await
        .map_err(|err| e!(H3ConnectError::Connect, anyerr!(err)))?;

    trace!(status = %resp.status, "WT: CONNECT response received");

    if !resp.status.is_success() {
        return Err(e!(H3ConnectError::Rejected {
            status: resp.status,
        }));
    }

    // Run the relay handshake over per-message uni streams (a peer may drop
    // datagrams sent before the WebTransport session is fully established, losing
    // the server's challenge), then switch to the negotiated framing for the data
    // phase.
    let mut io = WtBytesFramed::new(conn.clone(), session_id, WtTransferMode::UniPerPacket);

    trace!("WT: starting relay handshake");
    handshake::clientside(&mut io, secret_key).await?;
    trace!("WT: relay handshake complete");

    io.set_transfer_mode(transfer_mode);

    let state = WtConnState {
        _conn: conn,
        _endpoint,
    };

    Ok((io, state, local_addr))
}

/// Convenience: run both phases in sequence. Used in tests.
#[cfg(test)]
pub(crate) async fn connect_h3(
    server_addr: SocketAddr,
    server_name: &str,
    tls_config: rustls::ClientConfig,
    secret_key: &SecretKey,
    transfer_mode: WtTransferMode,
) -> Result<(WtBytesFramed, WtConnState, SocketAddr), H3ConnectError> {
    let quic = quic_connect(server_addr, server_name, tls_config).await?;
    wt_handshake(quic, server_name, secret_key, transfer_mode).await
}
