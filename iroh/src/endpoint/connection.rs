//! The [`Connection`] wraps a `quinn::Connection`.
//!
//! The [`Connection`] is how you send data to and receive data from the remote endpoint.
//!
//! There are many transitions states between attempting to start a connection and
//! receiving a cryptographically secure connection.
//!
//! The main items in this module are:
//!
//! - [`Connection`] to create streams to talk to a remote endpoint.
//! - [`Connecting`] for operating on connections that haven't finished their handshake yet.
//! - [`Incoming`] to accept or reject an incoming connection.
//! - [`OutgoingZeroRttConnection`] to attempt to send 0-RTT data before the cryptographic
//!   handshake has completed.
//! - [`IncomingZeroRttConnection`] to attempt to read 0-RTT or send 0.5-RTT data before the cryptographic
//!   handshake has completed.
//!
//! [module docs]: crate
use std::{
    any::Any,
    future::{Future, IntoFuture},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey};
use futures_util::{FutureExt, future::Shared};
use iroh_base::{EndpointId, PublicKey};
use n0_error::{e, stack_error};
use n0_future::time::Duration;
use n0_watcher::Watcher;
use pin_project::pin_project;
use quinn::{
    AcceptBi, AcceptUni, ConnectionError, ConnectionStats, OpenBi, OpenUni, ReadDatagram,
    RetryError, SendDatagramError, ServerConfig, VarInt,
};
use tracing::warn;

use crate::{Endpoint, discovery::DiscoveryTask, endpoint::rtt_actor::RttMessage};

/// Future produced by [`Endpoint::accept`].
#[derive(derive_more::Debug)]
#[pin_project]
pub struct Accept<'a> {
    #[pin]
    #[debug("quinn::Accept")]
    pub(crate) inner: quinn::Accept<'a>,
    pub(crate) ep: Endpoint,
}

impl Future for Accept<'_> {
    type Output = Option<Incoming>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(inner)) => Poll::Ready(Some(Incoming {
                inner,
                ep: this.ep.clone(),
            })),
        }
    }
}

/// An incoming connection for which the server has not yet begun its parts of the
/// handshake.
#[derive(Debug)]
pub struct Incoming {
    inner: quinn::Incoming,
    ep: Endpoint,
}

impl Incoming {
    /// Attempts to accept this incoming connection (an error may still occur).
    ///
    /// Errors occurring here are likely not caused by the application or remote.  The QUIC
    /// connection listens on a normal UDP socket and any reachable network endpoint can
    /// send datagrams to it, solicited or not.  Even if the first few bytes look like a
    /// QUIC packet, it might not even be a QUIC packet that is being received.
    ///
    /// Thus it is common to simply log the errors here and accept them as something which
    /// can happen.
    pub fn accept(self) -> Result<Accepting, ConnectionError> {
        self.inner
            .accept()
            .map(|conn| Accepting::new(conn, self.ep))
    }

    /// Accepts this incoming connection using a custom configuration.
    ///
    /// See [`accept()`] for more details.
    ///
    /// [`accept()`]: Incoming::accept
    pub fn accept_with(
        self,
        server_config: Arc<ServerConfig>,
    ) -> Result<Accepting, ConnectionError> {
        self.inner
            .accept_with(server_config)
            .map(|conn| Accepting::new(conn, self.ep))
    }

    /// Rejects this incoming connection attempt.
    pub fn refuse(self) {
        self.inner.refuse()
    }

    /// Responds with a retry packet.
    ///
    /// This requires the client to retry with address validation.
    ///
    /// Errors if `remote_address_validated()` is true.
    #[allow(clippy::result_large_err)]
    pub fn retry(self) -> Result<(), RetryError> {
        self.inner.retry()
    }

    /// Ignores this incoming connection attempt, not sending any packet in response.
    pub fn ignore(self) {
        self.inner.ignore()
    }

    /// Returns the local IP address which was used when the peer established the
    /// connection.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.inner.local_ip()
    }

    /// Returns the peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Whether the socket address that is initiating this connection has been validated.
    ///
    /// This means that the sender of the initial packet has proved that they can receive
    /// traffic sent to `self.remote_address()`.
    pub fn remote_address_validated(&self) -> bool {
        self.inner.remote_address_validated()
    }
}

impl IntoFuture for Incoming {
    type Output = Result<Connection, ConnectingError>;
    type IntoFuture = IncomingFuture;

    fn into_future(self) -> Self::IntoFuture {
        IncomingFuture {
            inner: self.inner.into_future(),
            ep: self.ep,
        }
    }
}

/// Adaptor to let [`Incoming`] be `await`ed like a [`Connecting`].
#[derive(Debug)]
#[pin_project]
pub struct IncomingFuture {
    #[pin]
    inner: quinn::IncomingFuture,
    ep: Endpoint,
}

impl Future for IncomingFuture {
    type Output = Result<Connection, ConnectingError>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
            Poll::Ready(Ok(inner)) => {
                let conn = match conn_from_quinn_conn(inner) {
                    Ok(conn) => conn,
                    Err(err) => return Poll::Ready(Err(err.into())),
                };
                try_send_rtt_msg(conn.quinn_connection(), this.ep, conn.remote_id);
                Poll::Ready(Ok(conn))
            }
        }
    }
}
/// Extracts the ALPN protocol from the peer's handshake data.
fn alpn_from_quinn_conn(conn: &quinn::Connection) -> Option<Vec<u8>> {
    let data = conn.handshake_data()?;
    match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
        Ok(data) => data.protocol,
        Err(_) => None,
    }
}

async fn alpn_from_quinn_connecting(conn: &mut quinn::Connecting) -> Result<Vec<u8>, AlpnError> {
    let data = conn.handshake_data().await?;
    match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
        Ok(data) => match data.protocol {
            Some(protocol) => Ok(protocol),
            None => Err(e!(AlpnError::Unavailable)),
        },
        Err(_) => Err(e!(AlpnError::UnknownHandshake)),
    }
}

#[stack_error(add_meta, derive, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum AuthenticationError {
    #[error(transparent)]
    RemoteId { source: RemoteEndpointIdError },
    #[error("no ALPN provided")]
    NoAlpn {},
    #[error(transparent)]
    ConnectionError {
        #[error(std_err)]
        source: ConnectionError,
    },
}

/// Converts a `quinn::Connection` to a `Connection`.
///
/// ## Errors
///
/// Returns a [`AuthenticationError`] if the handshake data has
/// not completed, or if no alpn was set by the remote node.
fn conn_from_quinn_conn(conn: quinn::Connection) -> Result<Connection, AuthenticationError> {
    if let Some(reason) = conn.close_reason() {
        return Err(e!(AuthenticationError::ConnectionError { source: reason }));
    }
    Ok(Connection {
        remote_id: remote_id_from_quinn_conn(&conn)?,
        alpn: alpn_from_quinn_conn(&conn).ok_or_else(|| e!(AuthenticationError::NoAlpn))?,
        inner: conn,
    })
}

/// Returns the [`PublicKey`] from the peer's TLS certificate.
///
/// The [`PublicKey`] of an endpoint is also known as an [`PublicKey`].  This [`PublicKey`] is
/// included in the TLS certificate presented during the handshake when connecting.
/// This function allows you to get the [`PublicKey`] of the remote endpoint of this
/// connection.
///
/// [`PublicKey`]: iroh_base::PublicKey
fn remote_id_from_quinn_conn(
    conn: &quinn::Connection,
) -> Result<PublicKey, RemoteEndpointIdError> {
    let data = conn.peer_identity();
    match data {
        None => {
            warn!("no peer certificate found");
            Err(RemoteEndpointIdError::new())
        }
        Some(data) => match data.downcast::<Vec<rustls::pki_types::CertificateDer>>() {
            Ok(certs) => {
                if certs.len() != 1 {
                    warn!(
                        "expected a single peer certificate, but {} found",
                        certs.len()
                    );
                    return Err(RemoteEndpointIdError::new());
                }

                let peer_id = PublicKey::from_verifying_key(
                    VerifyingKey::from_public_key_der(&certs[0])
                        .map_err(|_| RemoteEndpointIdError::new())?,
                );

                Ok(peer_id)
            }
            Err(err) => {
                warn!("invalid peer certificate: {:?}", err);
                Err(RemoteEndpointIdError::new())
            }
        },
    }
}

/// An outgoing connection in progress.
///
/// This future resolves to a [`Connection`] once the handshake completes.
#[derive(derive_more::Debug)]
#[pin_project]
pub struct Connecting {
    #[pin]
    inner: quinn::Connecting,
    ep: Endpoint,
    /// `Some(remote_id)` if this is an outgoing connection, `None` if this is an incoming conn
    remote_endpoint_id: PublicKey,
    /// We run discovery as long as we haven't established a connection yet.
    #[debug("Option<DiscoveryTask>")]
    _discovery_drop_guard: Option<DiscoveryTask>,
}

/// In-progress connection attempt future
#[derive(derive_more::Debug)]
#[pin_project]
pub struct Accepting {
    #[pin]
    inner: quinn::Connecting,
    ep: Endpoint,
}

#[stack_error(add_meta, derive, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum AlpnError {
    #[error(transparent)]
    ConnectionError {
        #[error(std_err)]
        source: ConnectionError,
    },
    #[error("No ALPN available")]
    Unavailable,
    #[error("Unknown handshake type")]
    UnknownHandshake,
}

#[stack_error(add_meta, derive, from_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ConnectingError {
    #[error(transparent)]
    ConnectionError {
        #[error(std_err)]
        source: ConnectionError,
    },
    #[error("Failure finalizing the handshake")]
    HandshakeFailure { source: AuthenticationError },
}

impl Connecting {
    pub(crate) fn new(
        inner: quinn::Connecting,
        ep: Endpoint,
        remote_endpoint_id: PublicKey,
        _discovery_drop_guard: Option<DiscoveryTask>,
    ) -> Self {
        Self {
            inner,
            ep,
            remote_endpoint_id,
            _discovery_drop_guard,
        }
    }

    /// Converts this [`Connecting`] into a 0-RTT connection at the cost of weakened security.
    ///
    /// If 0-RTT can be attempted, returns a [`OutgoingZeroRttConnection`], which represents
    /// outgoing 0-RTT connection.
    ///
    /// If the 0-RTT cannot even be attempted, returns back the same [`Connecting`] without
    /// changes. You can still `.await` this [`Connecting`] to get a normal [`Connection`].
    ///
    /// The [`OutgoingZeroRttConnection`] will attempt to resume a previous TLS session. However,
    /// **the remote endpoint may actually _reject_ the 0-RTT data--yet still accept
    /// the connection attempt in general**, once the handshake has completed.
    ///
    /// This possibility of whether the 0-RTT data was accepted or rejected is conveyed
    /// through the [`ZeroRttStatus`] after calling [`OutgoingZeroRttConnection::handshake_completed`].
    /// When the handshake completes, it returns [`ZeroRttStatus::Accepted`] if the 0-RTT data
    /// was accepted and [`ZeroRttStatus::Rejected`] if it was rejected. If it was rejected, the
    /// existence of any streams opened and application data sent prior to the handshake
    /// completing will not be conveyed to the remote application, and local operations on them
    /// will return `ZeroRttRejected` errors.
    ///
    /// A server may reject 0-RTT data at its discretion, but accepting 0-RTT data requires the
    /// relevant resumption state to be stored in the server, which servers may limit or lose for
    /// various reasons including not persisting resumption state across server restarts.
    ///
    /// ## Security
    ///
    /// This enables transmission of 0-RTT data, which is vulnerable to replay attacks, and
    /// should therefore never invoke non-idempotent operations.
    ///
    /// You can use [`RecvStream::is_0rtt`] to check whether a stream has been opened in 0-RTT
    /// and thus whether parts of the stream are operating under this reduced security level.
    ///
    /// See also documentation for [`Accepting::into_0rtt`].
    ///
    /// [`RecvStream::is_0rtt`]: quinn::RecvStream::is_0rtt
    #[allow(clippy::result_large_err)]
    pub fn into_0rtt(self) -> Result<OutgoingZeroRttConnection, Connecting> {
        match self.inner.into_0rtt() {
            Ok((inner, zrtt_accepted)) => {
                // This call is why `self.remote_endpoint_id` was introduced.
                // When we `Connecting::into_0rtt`, then we don't yet have `handshake_data`
                // in our `Connection`, thus `try_send_rtt_msg` won't be able to pick up
                // `Connection::remote_endpoint_id`.
                // Instead, we provide `self.remote_endpoint_id` here - we know it in advance,
                // after all.
                try_send_rtt_msg(&inner, &self.ep, self.remote_endpoint_id);
                Ok(OutgoingZeroRttConnection {
                    inner,
                    accepted: ZeroRttAccepted {
                        inner: zrtt_accepted,
                        _discovery_drop_guard: self._discovery_drop_guard,
                    }
                    .shared(),
                })
            }
            Err(inner) => Err(Self {
                inner,
                ep: self.ep,
                remote_endpoint_id: self.remote_endpoint_id,
                _discovery_drop_guard: self._discovery_drop_guard,
            }),
        }
    }

    /// Parameters negotiated during the handshake
    pub async fn handshake_data(&mut self) -> Result<Box<dyn Any>, ConnectionError> {
        self.inner.handshake_data().await
    }

    /// Extracts the ALPN protocol from the peer's handshake data.
    pub async fn alpn(&mut self) -> Result<Vec<u8>, AlpnError> {
        alpn_from_quinn_connecting(&mut self.inner).await
    }

    /// Returns the [`EndpointId`] of the endpoint that this connection attempt tries to connect to.
    pub fn remote_id(&self) -> EndpointId {
        self.remote_endpoint_id.into()
    }
}

impl Future for Connecting {
    type Output = Result<Connection, ConnectingError>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
            Poll::Ready(Ok(inner)) => {
                let conn = match conn_from_quinn_conn(inner) {
                    Ok(conn) => conn,
                    Err(err) => {
                        return Poll::Ready(Err(err.into()));
                    }
                };

                try_send_rtt_msg(conn.quinn_connection(), this.ep, conn.remote_id);
                Poll::Ready(Ok(conn))
            }
        }
    }
}

impl Accepting {
    pub(crate) fn new(inner: quinn::Connecting, ep: Endpoint) -> Self {
        Self { inner, ep }
    }

    /// Converts this [`Accepting`] into a 0-RTT or 0.5-RTT connection at the cost of weakened
    /// security.
    ///
    /// Returns a [`IncomingZeroRttConnection`], which represents an incoming 0-RTT or 0.5-RTT connection.
    ///
    /// If the connection was initiated with 0-RTT by the remote endpoint, the local endpoint
    /// might accept the 0-RTT attempt, allowing the local endpoint to receive application streams
    /// and data before the handshake finishes.
    ///
    /// Otherwise this will enable 0.5-RTT, allowing the [`IncomingZeroRttConnection`] to open streams and send
    /// data before the handshake finishes.
    ///
    /// ## Security
    ///
    /// Transmitted 0-RTT data from the client is vulnerable to replay attacks, and should
    /// therefore never invoke non-idempotent operations.
    ///
    /// Transmission of 0.5-RTT data from the server may be sent before TLS client authentication
    /// has occurred, and should therefore not be used to send data for which client
    /// authentication is required.
    ///
    /// You can use [`RecvStream::is_0rtt`] to check whether a stream has been opened in 0-RTT
    /// and thus whether parts of the stream are operating under this reduced security level.
    ///
    /// See also documentation for [`Connecting::into_0rtt`].
    ///
    /// [`RecvStream::is_0rtt`]: quinn::RecvStream::is_0rtt
    pub fn into_0rtt(self) -> IncomingZeroRttConnection {
        let (inner, accepted) = self
            .inner
            .into_0rtt()
            .expect("incoming connections can always be converted to 0-RTT");
        IncomingZeroRttConnection {
            accepted: ZeroRttAccepted {
                inner: accepted,
                _discovery_drop_guard: None,
            },
            inner,
        }
    }

    /// Parameters negotiated during the handshake
    pub async fn handshake_data(&mut self) -> Result<Box<dyn Any>, ConnectionError> {
        self.inner.handshake_data().await
    }

    /// Extracts the ALPN protocol from the peer's handshake data.
    pub async fn alpn(&mut self) -> Result<Vec<u8>, AlpnError> {
        alpn_from_quinn_connecting(&mut self.inner).await
    }
}

impl Future for Accepting {
    type Output = Result<Connection, ConnectingError>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
            Poll::Ready(Ok(inner)) => {
                let conn = match conn_from_quinn_conn(inner) {
                    Ok(conn) => conn,
                    Err(err) => return Poll::Ready(Err(err.into())),
                };

                try_send_rtt_msg(conn.quinn_connection(), this.ep, conn.remote_id);
                Poll::Ready(Ok(conn))
            }
        }
    }
}

/// Future that completes when a connection is fully established.
///
/// For clients, the resulting value indicates if 0-RTT was accepted. For servers, the resulting
/// value is meaningless.
#[derive(derive_more::Debug)]
#[debug("ZeroRttAccepted")]
struct ZeroRttAccepted {
    inner: quinn::ZeroRttAccepted,
    /// When we call `Connecting::into_0rtt`, we don't want to stop discovery, so we transfer the task
    /// to this future.
    /// When `quinn::ZeroRttAccepted` resolves, we've successfully received data from the remote.
    /// Thus, that's the right time to drop discovery to preserve the behaviour similar to
    /// `Connecting` -> `Connection` without 0-RTT.
    /// Should we eventually decide to keep the discovery task alive for the duration of the whole
    /// `Connection`, then this task should be transferred to the `Connection` instead of here.
    _discovery_drop_guard: Option<DiscoveryTask>,
}

impl Future for ZeroRttAccepted {
    type Output = bool;
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// The client side of a 0-RTT connection.
///
/// This is created using [`Connecting::into_0rtt`].
///
/// Creating a `OutgoingZeroRttConnection` means that the endpoint is capable
/// of attempting a 0-RTT connection with the remote. The remote may still
/// reject the 0-RTT connection. In which case, any data sent before the
/// handshake has completed may need to be resent.
///
/// Look at the [`OutgoingZeroRttConnection::handshake_completed`] method for
/// more details.
#[derive(Debug, Clone)]
pub struct OutgoingZeroRttConnection {
    inner: quinn::Connection,
    accepted: Shared<ZeroRttAccepted>,
}

/// Returned from [`OutgoingZeroRttConnection::handshake_completed`].
#[derive(Debug)]
pub enum ZeroRttStatus {
    /// If the 0-RTT data was accepted, you can continue to use any streams
    /// that were created before the handshake was completed.
    Accepted(Connection),
    /// If the 0-RTT data was rejected, any streams that were created before
    /// the handshake was completed will error and any data that was
    /// previously sent on those streams will need to be resent.
    Rejected(Connection),
}

impl OutgoingZeroRttConnection {
    /// Waits until the full handshake occurs and returns a [`ZeroRttStatus`].
    ///
    /// If `ZeroRttStatus::Accepted` is returned, than any streams created before
    /// the handshake has completed can still be used.
    ///
    /// If `ZeroRttStatus::Rejected` is returned, than any streams created before
    /// the handshake will error and any data sent should be re-sent on a
    /// new stream.
    ///
    /// This may fail with [`AuthenticationError::ConnectionError`], if there was
    /// some general failure with the connection, such as a network timeout since
    /// we initiated the connection.
    ///
    /// This may fail with other [`AuthenticationError`]s, if the other side
    /// doesn't use the right TLS authentication, which usually every iroh endpoint
    /// uses and requires.
    ///
    /// Thus, those errors should only occur if someone connects to you with a
    /// modified iroh endpoint or with a plain QUIC client.
    pub async fn handshake_completed(&self) -> Result<ZeroRttStatus, AuthenticationError> {
        let accepted = self.accepted.clone().await;
        let conn = conn_from_quinn_conn(self.inner.clone())?;

        Ok(match accepted {
            true => ZeroRttStatus::Accepted(conn),
            false => ZeroRttStatus::Rejected(conn),
        })
    }

    /// Initiates a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won’t be notified that a stream has been opened until the
    /// stream is actually used.
    #[inline]
    pub fn open_uni(&self) -> OpenUni<'_> {
        self.inner.open_uni()
    }

    /// Initiates a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the
    /// stream is actually used. Calling [`open_bi`] then waiting on the [`RecvStream`]
    /// without writing anything to [`SendStream`] will never succeed.
    ///
    /// [`open_bi`]: Connection::open_bi
    /// [`SendStream`]: quinn::SendStream
    /// [`RecvStream`]: quinn::RecvStream
    #[inline]
    pub fn open_bi(&self) -> OpenBi<'_> {
        self.inner.open_bi()
    }

    /// Accepts the next incoming uni-directional stream.
    #[inline]
    pub fn accept_uni(&self) -> AcceptUni<'_> {
        self.inner.accept_uni()
    }

    /// Accept the next incoming bidirectional stream.
    ///
    /// **Important Note**: The peer that calls [`open_bi`] must write to its [`SendStream`]
    /// before the peer `Connection` is able to accept the stream using
    /// `accept_bi()`. Calling [`open_bi`] then waiting on the [`RecvStream`] without
    /// writing anything to the connected [`SendStream`] will never succeed.
    ///
    /// [`open_bi`]: Connection::open_bi
    /// [`SendStream`]: quinn::SendStream
    /// [`RecvStream`]: quinn::RecvStream
    #[inline]
    pub fn accept_bi(&self) -> AcceptBi<'_> {
        self.inner.accept_bi()
    }

    /// Receives an application datagram.
    #[inline]
    pub fn read_datagram(&self) -> ReadDatagram<'_> {
        self.inner.read_datagram()
    }

    /// Wait for the connection to be closed for any reason.
    ///
    /// Despite the return type's name, closed connections are often not an error condition
    /// at the application layer. Cases that might be routine include
    /// [`ConnectionError::LocallyClosed`] and [`ConnectionError::ApplicationClosed`].
    #[inline]
    pub async fn closed(&self) -> ConnectionError {
        self.inner.closed().await
    }

    /// If the connection is closed, the reason why.
    ///
    /// Returns `None` if the connection is still open.
    #[inline]
    pub fn close_reason(&self) -> Option<ConnectionError> {
        self.inner.close_reason()
    }

    /// Closes the connection immediately.
    ///
    /// Pending operations will fail immediately with [`ConnectionError::LocallyClosed`]. No
    /// more data is sent to the peer and the peer may drop buffered data upon receiving the
    /// CONNECTION_CLOSE frame.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the
    /// peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds
    /// that it is preserved in full, it should be kept under 1KiB.
    ///
    /// # Gracefully closing a connection
    ///
    /// Only the peer last receiving application data can be certain that all data is
    /// delivered. The only reliable action it can then take is to close the connection,
    /// potentially with a custom error code. The delivery of the final CONNECTION_CLOSE
    /// frame is very likely if both endpoints stay online long enough, calling
    /// [`Endpoint::close`] will wait to provide sufficient time. Otherwise, the remote peer
    /// will time out the connection, provided that the idle timeout is not disabled.
    ///
    /// The sending side can not guarantee all stream data is delivered to the remote
    /// application. It only knows the data is delivered to the QUIC stack of the remote
    /// endpoint. Once the local side sends a CONNECTION_CLOSE frame in response to calling
    /// [`close`] the remote endpoint may drop any data it received but is as yet
    /// undelivered to the application, including data that was acknowledged as received to
    /// the local endpoint.
    ///
    /// [`close`]: Connection::close
    #[inline]
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.inner.close(error_code, reason)
    }

    /// Transmits `data` as an unreliable, unordered application datagram.
    ///
    /// Application datagrams are a low-level primitive. They may be lost or delivered out
    /// of order, and `data` must both fit inside a single QUIC packet and be smaller than
    /// the maximum dictated by the peer.
    #[inline]
    pub fn send_datagram(&self, data: bytes::Bytes) -> Result<(), SendDatagramError> {
        self.inner.send_datagram(data)
    }

    // TODO: It seems `SendDatagram` is not yet exposed by quinn.  This has been fixed
    //       upstream and will be in the next release.
    // /// Transmits `data` as an unreliable, unordered application datagram
    // ///
    // /// Unlike [`send_datagram()`], this method will wait for buffer space during congestion
    // /// conditions, which effectively prioritizes old datagrams over new datagrams.
    // ///
    // /// See [`send_datagram()`] for details.
    // ///
    // /// [`send_datagram()`]: Connection::send_datagram
    // #[inline]
    // pub fn send_datagram_wait(&self, data: bytes::Bytes) -> SendDatagram<'_> {
    //     self.inner.send_datagram_wait(data)
    // }

    /// Computes the maximum size of datagrams that may be passed to [`send_datagram`].
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path
    /// MTU estimate. The peer can also enforce an arbitrarily small fixed limit, but if the
    /// peer's limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// [`send_datagram`]: Self::send_datagram
    #[inline]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// Bytes available in the outgoing datagram buffer.
    ///
    /// When greater than zero, calling [`send_datagram`] with a
    /// datagram of at most this size is guaranteed not to cause older datagrams to be
    /// dropped.
    ///
    /// [`send_datagram`]: Self::send_datagram
    #[inline]
    pub fn datagram_send_buffer_space(&self) -> usize {
        self.inner.datagram_send_buffer_space()
    }

    /// Current best estimate of this connection's latency (round-trip-time).
    #[inline]
    pub fn rtt(&self) -> Duration {
        self.inner.rtt()
    }

    /// Returns connection statistics.
    #[inline]
    pub fn stats(&self) -> ConnectionStats {
        self.inner.stats()
    }

    /// Current state of the congestion control algorithm, for debugging purposes.
    #[inline]
    pub fn congestion_state(&self) -> Box<dyn quinn_proto::congestion::Controller> {
        self.inner.congestion_state()
    }

    /// Parameters negotiated during the handshake.
    ///
    /// Guaranteed to return `Some` on fully established connections or after
    /// [`Connecting::handshake_data()`] succeeds. See that method's documentations for
    /// details on the returned value.
    ///
    /// [`Connection::handshake_data()`]: crate::endpoint::Connecting::handshake_data
    #[inline]
    pub fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    /// Extracts the ALPN protocol from the peer's handshake data.
    pub fn alpn(&self) -> Option<Vec<u8>> {
        alpn_from_quinn_conn(&self.inner)
    }

    /// Cryptographic identity of the peer.
    ///
    /// The dynamic type returned is determined by the configured [`Session`]. For the
    /// default `rustls` session, the return value can be [`downcast`] to a
    /// <code>Vec<[rustls::pki_types::CertificateDer]></code>
    ///
    /// [`Session`]: quinn_proto::crypto::Session
    /// [`downcast`]: Box::downcast
    #[inline]
    pub fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    /// Returns the [`PublicKey`] from the peer's TLS certificate.
    ///
    /// The [`PublicKey`] of an endpoint is also known as an [`PublicKey`].  This [`PublicKey`] is
    /// included in the TLS certificate presented during the handshake when connecting.
    /// This function allows you to get the [`PublicKey`] of the remote endpoint of this
    /// connection.
    ///
    /// [`PublicKey`]: iroh_base::PublicKey
    pub fn remote_id(&self) -> Result<EndpointId, RemoteEndpointIdError> {
        remote_id_from_quinn_conn(&self.inner).map(EndpointId::from)
    }

    /// A stable identifier for this connection.
    ///
    /// Peer addresses and connection IDs can change, but this value will remain fixed for
    /// the lifetime of the connection.
    #[inline]
    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }

    /// Derives keying material from this connection's TLS session secrets.
    ///
    /// When both peers call this method with the same `label` and `context`
    /// arguments and `output` buffers of equal length, they will get the
    /// same sequence of bytes in `output`. These bytes are cryptographically
    /// strong and pseudorandom, and are suitable for use as keying material.
    ///
    /// See [RFC5705](https://tools.ietf.org/html/rfc5705) for more information.
    #[inline]
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), quinn_proto::crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }

    /// Modifies the number of unidirectional streams that may be concurrently opened.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already
    /// open. Large `count`s increase both minimum and worst-case memory consumption.
    #[inline]
    pub fn set_max_concurrent_uni_streams(&self, count: VarInt) {
        self.inner.set_max_concurrent_uni_streams(count)
    }

    /// See [`quinn_proto::TransportConfig::receive_window`].
    #[inline]
    pub fn set_receive_window(&self, receive_window: VarInt) {
        self.inner.set_receive_window(receive_window)
    }

    /// Modifies the number of bidirectional streams that may be concurrently opened.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already
    /// open. Large `count`s increase both minimum and worst-case memory consumption.
    #[inline]
    pub fn set_max_concurrent_bi_streams(&self, count: VarInt) {
        self.inner.set_max_concurrent_bi_streams(count)
    }
}

/// A QUIC connection on the server-side that can possibly accept 0-RTT data.
///
/// It is very similar to a `Connection`, but the `IncomingZeroRttConnection::remote_id`
/// and `IncomingZeroRttConnection::alpn` may not be set yet, since the handshake has
/// not necessarily occurred yet.
///
/// If the `IncomingZeroRttConnection` has rejected 0-RTT or does not have enough information
/// to accept 0-RTT, any received 0-RTT packets will simply be dropped before
/// reaching any receive streams.
///
/// Any streams that are created to send or receive data can continue to be used
/// even after the handshake has completed and we are no longer in a 0-RTT
/// situation.
///
/// Use the [`IncomingZeroRttConnection::handshake_completed`] method to get a [`Connection`] from a
/// `IncomingZeroRttConnection`. This waits until 0-RTT connection has completed
/// the handshake and can now confidently derive the ALPN and the
/// [`PublicKey`] of the remote endpoint.
#[derive(Debug)]
pub struct IncomingZeroRttConnection {
    inner: quinn::Connection,
    accepted: ZeroRttAccepted,
}

impl IncomingZeroRttConnection {
    /// Waits until the full handshake occurs and then returns a [`Connection`].
    ///
    /// This may fail with [`AuthenticationError::ConnectionError`], if there was
    /// some general failure with the connection, such as a network timeout since
    /// we accepted the connection.
    ///
    /// This may fail with other [`AuthenticationError`]s, if the other side
    /// doesn't use the right TLS authentication, which usually every iroh endpoint
    /// uses and requires.
    ///
    /// Thus, those errors should only occur if someone connects to you with a
    /// modified iroh endpoint or with a plain QUIC client.
    pub async fn handshake_completed(self) -> Result<Connection, AuthenticationError> {
        self.accepted.await;
        conn_from_quinn_conn(self.inner)
    }

    /// Initiates a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won’t be notified that a stream has been opened until the
    /// stream is actually used.
    #[inline]
    pub fn open_uni(&self) -> OpenUni<'_> {
        self.inner.open_uni()
    }

    /// Initiates a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the
    /// stream is actually used. Calling [`open_bi`] then waiting on the [`RecvStream`]
    /// without writing anything to [`SendStream`] will never succeed.
    ///
    /// [`open_bi`]: Connection::open_bi
    /// [`SendStream`]: quinn::SendStream
    /// [`RecvStream`]: quinn::RecvStream
    #[inline]
    pub fn open_bi(&self) -> OpenBi<'_> {
        self.inner.open_bi()
    }

    /// Accepts the next incoming uni-directional stream.
    #[inline]
    pub fn accept_uni(&self) -> AcceptUni<'_> {
        self.inner.accept_uni()
    }

    /// Accept the next incoming bidirectional stream.
    ///
    /// **Important Note**: The peer that calls [`open_bi`] must write to its [`SendStream`]
    /// before the peer `Connection` is able to accept the stream using
    /// `accept_bi()`. Calling [`open_bi`] then waiting on the [`RecvStream`] without
    /// writing anything to the connected [`SendStream`] will never succeed.
    ///
    /// [`open_bi`]: Connection::open_bi
    /// [`SendStream`]: quinn::SendStream
    /// [`RecvStream`]: quinn::RecvStream
    #[inline]
    pub fn accept_bi(&self) -> AcceptBi<'_> {
        self.inner.accept_bi()
    }

    /// Receives an application datagram.
    #[inline]
    pub fn read_datagram(&self) -> ReadDatagram<'_> {
        self.inner.read_datagram()
    }

    /// Wait for the connection to be closed for any reason.
    ///
    /// Despite the return type's name, closed connections are often not an error condition
    /// at the application layer. Cases that might be routine include
    /// [`ConnectionError::LocallyClosed`] and [`ConnectionError::ApplicationClosed`].
    #[inline]
    pub async fn closed(&self) -> ConnectionError {
        self.inner.closed().await
    }

    /// If the connection is closed, the reason why.
    ///
    /// Returns `None` if the connection is still open.
    #[inline]
    pub fn close_reason(&self) -> Option<ConnectionError> {
        self.inner.close_reason()
    }

    /// Closes the connection immediately.
    ///
    /// Pending operations will fail immediately with [`ConnectionError::LocallyClosed`]. No
    /// more data is sent to the peer and the peer may drop buffered data upon receiving the
    /// CONNECTION_CLOSE frame.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the
    /// peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds
    /// that it is preserved in full, it should be kept under 1KiB.
    ///
    /// # Gracefully closing a connection
    ///
    /// Only the peer last receiving application data can be certain that all data is
    /// delivered. The only reliable action it can then take is to close the connection,
    /// potentially with a custom error code. The delivery of the final CONNECTION_CLOSE
    /// frame is very likely if both endpoints stay online long enough, calling
    /// [`Endpoint::close`] will wait to provide sufficient time. Otherwise, the remote peer
    /// will time out the connection, provided that the idle timeout is not disabled.
    ///
    /// The sending side can not guarantee all stream data is delivered to the remote
    /// application. It only knows the data is delivered to the QUIC stack of the remote
    /// endpoint. Once the local side sends a CONNECTION_CLOSE frame in response to calling
    /// [`close`] the remote endpoint may drop any data it received but is as yet
    /// undelivered to the application, including data that was acknowledged as received to
    /// the local endpoint.
    ///
    /// [`close`]: Connection::close
    #[inline]
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.inner.close(error_code, reason)
    }

    /// Transmits `data` as an unreliable, unordered application datagram.
    ///
    /// Application datagrams are a low-level primitive. They may be lost or delivered out
    /// of order, and `data` must both fit inside a single QUIC packet and be smaller than
    /// the maximum dictated by the peer.
    #[inline]
    pub fn send_datagram(&self, data: bytes::Bytes) -> Result<(), SendDatagramError> {
        self.inner.send_datagram(data)
    }

    // TODO: It seems `SendDatagram` is not yet exposed by quinn.  This has been fixed
    //       upstream and will be in the next release.
    // /// Transmits `data` as an unreliable, unordered application datagram
    // ///
    // /// Unlike [`send_datagram()`], this method will wait for buffer space during congestion
    // /// conditions, which effectively prioritizes old datagrams over new datagrams.
    // ///
    // /// See [`send_datagram()`] for details.
    // ///
    // /// [`send_datagram()`]: Connection::send_datagram
    // #[inline]
    // pub fn send_datagram_wait(&self, data: bytes::Bytes) -> SendDatagram<'_> {
    //     self.inner.send_datagram_wait(data)
    // }

    /// Computes the maximum size of datagrams that may be passed to [`send_datagram`].
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path
    /// MTU estimate. The peer can also enforce an arbitrarily small fixed limit, but if the
    /// peer's limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// [`send_datagram`]: Self::send_datagram
    #[inline]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// Bytes available in the outgoing datagram buffer.
    ///
    /// When greater than zero, calling [`send_datagram`] with a
    /// datagram of at most this size is guaranteed not to cause older datagrams to be
    /// dropped.
    ///
    /// [`send_datagram`]: Self::send_datagram
    #[inline]
    pub fn datagram_send_buffer_space(&self) -> usize {
        self.inner.datagram_send_buffer_space()
    }

    /// Current best estimate of this connection's latency (round-trip-time).
    #[inline]
    pub fn rtt(&self) -> Duration {
        self.inner.rtt()
    }

    /// Returns connection statistics.
    #[inline]
    pub fn stats(&self) -> ConnectionStats {
        self.inner.stats()
    }

    /// Current state of the congestion control algorithm, for debugging purposes.
    #[inline]
    pub fn congestion_state(&self) -> Box<dyn quinn_proto::congestion::Controller> {
        self.inner.congestion_state()
    }

    /// Parameters negotiated during the handshake.
    ///
    /// Guaranteed to return `Some` on fully established connections or after
    /// [`Connecting::handshake_data()`] succeeds. See that method's documentations for
    /// details on the returned value.
    ///
    /// [`Connection::handshake_data()`]: crate::endpoint::Connecting::handshake_data
    #[inline]
    pub fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    /// Extracts the ALPN protocol from the peer's handshake data.
    pub fn alpn(&self) -> Option<Vec<u8>> {
        alpn_from_quinn_conn(&self.inner)
    }

    /// Cryptographic identity of the peer.
    ///
    /// The dynamic type returned is determined by the configured [`Session`]. For the
    /// default `rustls` session, the return value can be [`downcast`] to a
    /// <code>Vec<[rustls::pki_types::CertificateDer]></code>
    ///
    /// [`Session`]: quinn_proto::crypto::Session
    /// [`downcast`]: Box::downcast
    #[inline]
    pub fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    /// Returns the [`PublicKey`] from the peer's TLS certificate.
    ///
    /// The [`PublicKey`] of an endpoint is also known as an [`PublicKey`].  This [`PublicKey`] is
    /// included in the TLS certificate presented during the handshake when connecting.
    /// This function allows you to get the [`PublicKey`] of the remote endpoint of this
    /// connection.
    ///
    /// [`PublicKey`]: iroh_base::PublicKey
    pub fn remote_id(&self) -> Result<EndpointId, RemoteEndpointIdError> {
        remote_id_from_quinn_conn(&self.inner).map(EndpointId::from)
    }

    /// A stable identifier for this connection.
    ///
    /// Peer addresses and connection IDs can change, but this value will remain fixed for
    /// the lifetime of the connection.
    #[inline]
    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }

    /// Derives keying material from this connection's TLS session secrets.
    ///
    /// When both peers call this method with the same `label` and `context`
    /// arguments and `output` buffers of equal length, they will get the
    /// same sequence of bytes in `output`. These bytes are cryptographically
    /// strong and pseudorandom, and are suitable for use as keying material.
    ///
    /// See [RFC5705](https://tools.ietf.org/html/rfc5705) for more information.
    #[inline]
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), quinn_proto::crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }

    /// Modifies the number of unidirectional streams that may be concurrently opened.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already
    /// open. Large `count`s increase both minimum and worst-case memory consumption.
    #[inline]
    pub fn set_max_concurrent_uni_streams(&self, count: VarInt) {
        self.inner.set_max_concurrent_uni_streams(count)
    }

    /// See [`quinn_proto::TransportConfig::receive_window`].
    #[inline]
    pub fn set_receive_window(&self, receive_window: VarInt) {
        self.inner.set_receive_window(receive_window)
    }

    /// Modifies the number of bidirectional streams that may be concurrently opened.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already
    /// open. Large `count`s increase both minimum and worst-case memory consumption.
    #[inline]
    pub fn set_max_concurrent_bi_streams(&self, count: VarInt) {
        self.inner.set_max_concurrent_bi_streams(count)
    }
}

/// A QUIC connection.
///
/// If all references to a connection (including every clone of the Connection handle,
/// streams of incoming streams, and the various stream types) have been dropped, then the
/// connection will be automatically closed with an error_code of 0 and an empty reason. You
/// can also close the connection explicitly by calling [`Connection::close`].
///
/// Closing the connection immediately abandons efforts to deliver data to the peer. Upon
/// receiving CONNECTION_CLOSE the peer may drop any stream data not yet delivered to the
/// application. [`Connection::close`] describes in more detail how to gracefully close a
/// connection without losing application data.
///
/// May be cloned to obtain another handle to the same connection.
#[derive(derive_more::Debug, Clone)]
pub struct Connection {
    inner: quinn::Connection,
    remote_id: PublicKey,
    alpn: Vec<u8>,
}

#[allow(missing_docs)]
#[stack_error(add_meta, derive)]
#[error("Protocol error: no remote id available")]
pub struct RemoteEndpointIdError;

impl Connection {
    fn quinn_connection(&self) -> &quinn::Connection {
        &self.inner
    }

    /// Initiates a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won’t be notified that a stream has been opened until the
    /// stream is actually used.
    #[inline]
    pub fn open_uni(&self) -> OpenUni<'_> {
        self.inner.open_uni()
    }

    /// Initiates a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the
    /// stream is actually used. Calling [`open_bi`] then waiting on the [`RecvStream`]
    /// without writing anything to [`SendStream`] will never succeed.
    ///
    /// [`open_bi`]: Connection::open_bi
    /// [`SendStream`]: quinn::SendStream
    /// [`RecvStream`]: quinn::RecvStream
    #[inline]
    pub fn open_bi(&self) -> OpenBi<'_> {
        self.inner.open_bi()
    }

    /// Accepts the next incoming uni-directional stream.
    #[inline]
    pub fn accept_uni(&self) -> AcceptUni<'_> {
        self.inner.accept_uni()
    }

    /// Accept the next incoming bidirectional stream.
    ///
    /// **Important Note**: The peer that calls [`open_bi`] must write to its [`SendStream`]
    /// before the peer `Connection` is able to accept the stream using
    /// `accept_bi()`. Calling [`open_bi`] then waiting on the [`RecvStream`] without
    /// writing anything to the connected [`SendStream`] will never succeed.
    ///
    /// [`open_bi`]: Connection::open_bi
    /// [`SendStream`]: quinn::SendStream
    /// [`RecvStream`]: quinn::RecvStream
    #[inline]
    pub fn accept_bi(&self) -> AcceptBi<'_> {
        self.inner.accept_bi()
    }

    /// Receives an application datagram.
    #[inline]
    pub fn read_datagram(&self) -> ReadDatagram<'_> {
        self.inner.read_datagram()
    }

    /// Wait for the connection to be closed for any reason.
    ///
    /// Despite the return type's name, closed connections are often not an error condition
    /// at the application layer. Cases that might be routine include
    /// [`ConnectionError::LocallyClosed`] and [`ConnectionError::ApplicationClosed`].
    #[inline]
    pub async fn closed(&self) -> ConnectionError {
        self.inner.closed().await
    }

    /// If the connection is closed, the reason why.
    ///
    /// Returns `None` if the connection is still open.
    #[inline]
    pub fn close_reason(&self) -> Option<ConnectionError> {
        self.inner.close_reason()
    }

    /// Closes the connection immediately.
    ///
    /// Pending operations will fail immediately with [`ConnectionError::LocallyClosed`]. No
    /// more data is sent to the peer and the peer may drop buffered data upon receiving the
    /// CONNECTION_CLOSE frame.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the
    /// peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds
    /// that it is preserved in full, it should be kept under 1KiB.
    ///
    /// # Gracefully closing a connection
    ///
    /// Only the peer last receiving application data can be certain that all data is
    /// delivered. The only reliable action it can then take is to close the connection,
    /// potentially with a custom error code. The delivery of the final CONNECTION_CLOSE
    /// frame is very likely if both endpoints stay online long enough, calling
    /// [`Endpoint::close`] will wait to provide sufficient time. Otherwise, the remote peer
    /// will time out the connection, provided that the idle timeout is not disabled.
    ///
    /// The sending side can not guarantee all stream data is delivered to the remote
    /// application. It only knows the data is delivered to the QUIC stack of the remote
    /// endpoint. Once the local side sends a CONNECTION_CLOSE frame in response to calling
    /// [`close`] the remote endpoint may drop any data it received but is as yet
    /// undelivered to the application, including data that was acknowledged as received to
    /// the local endpoint.
    ///
    /// [`close`]: Connection::close
    #[inline]
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.inner.close(error_code, reason)
    }

    /// Transmits `data` as an unreliable, unordered application datagram.
    ///
    /// Application datagrams are a low-level primitive. They may be lost or delivered out
    /// of order, and `data` must both fit inside a single QUIC packet and be smaller than
    /// the maximum dictated by the peer.
    #[inline]
    pub fn send_datagram(&self, data: bytes::Bytes) -> Result<(), SendDatagramError> {
        self.inner.send_datagram(data)
    }

    // TODO: It seems `SendDatagram` is not yet exposed by quinn.  This has been fixed
    //       upstream and will be in the next release.
    // /// Transmits `data` as an unreliable, unordered application datagram
    // ///
    // /// Unlike [`send_datagram()`], this method will wait for buffer space during congestion
    // /// conditions, which effectively prioritizes old datagrams over new datagrams.
    // ///
    // /// See [`send_datagram()`] for details.
    // ///
    // /// [`send_datagram()`]: Connection::send_datagram
    // #[inline]
    // pub fn send_datagram_wait(&self, data: bytes::Bytes) -> SendDatagram<'_> {
    //     self.inner.send_datagram_wait(data)
    // }

    /// Computes the maximum size of datagrams that may be passed to [`send_datagram`].
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path
    /// MTU estimate. The peer can also enforce an arbitrarily small fixed limit, but if the
    /// peer's limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// [`send_datagram`]: Self::send_datagram
    #[inline]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// Bytes available in the outgoing datagram buffer.
    ///
    /// When greater than zero, calling [`send_datagram`] with a
    /// datagram of at most this size is guaranteed not to cause older datagrams to be
    /// dropped.
    ///
    /// [`send_datagram`]: Self::send_datagram
    #[inline]
    pub fn datagram_send_buffer_space(&self) -> usize {
        self.inner.datagram_send_buffer_space()
    }

    /// Current best estimate of this connection's latency (round-trip-time).
    #[inline]
    pub fn rtt(&self) -> Duration {
        self.inner.rtt()
    }

    /// Returns connection statistics.
    #[inline]
    pub fn stats(&self) -> ConnectionStats {
        self.inner.stats()
    }

    /// Current state of the congestion control algorithm, for debugging purposes.
    #[inline]
    pub fn congestion_state(&self) -> Box<dyn quinn_proto::congestion::Controller> {
        self.inner.congestion_state()
    }

    /// Parameters negotiated during the handshake.
    ///
    /// Guaranteed to return `Some` on fully established connections or after
    /// [`Connecting::handshake_data()`] succeeds. See that method's documentations for
    /// details on the returned value.
    ///
    /// [`Connection::handshake_data()`]: crate::endpoint::Connecting::handshake_data
    #[inline]
    pub fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    /// Extracts the ALPN protocol from the peer's handshake data.
    pub fn alpn(&self) -> &[u8] {
        &self.alpn
    }

    /// Cryptographic identity of the peer.
    ///
    /// The dynamic type returned is determined by the configured [`Session`]. For the
    /// default `rustls` session, the return value can be [`downcast`] to a
    /// <code>Vec<[rustls::pki_types::CertificateDer]></code>
    ///
    /// [`Session`]: quinn_proto::crypto::Session
    /// [`downcast`]: Box::downcast
    #[inline]
    pub fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    /// Returns the [`PublicKey`] from the peer's TLS certificate.
    ///
    /// The [`PublicKey`] of an endpoint is also known as an [`PublicKey`].  This [`PublicKey`] is
    /// included in the TLS certificate presented during the handshake when connecting.
    /// This function allows you to get the [`PublicKey`] of the remote endpoint of this
    /// connection.
    ///
    /// [`PublicKey`]: iroh_base::PublicKey
    pub fn remote_id(&self) -> EndpointId {
        self.remote_id.into()
    }

    /// A stable identifier for this connection.
    ///
    /// Peer addresses and connection IDs can change, but this value will remain fixed for
    /// the lifetime of the connection.
    #[inline]
    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }

    /// Derives keying material from this connection's TLS session secrets.
    ///
    /// When both peers call this method with the same `label` and `context`
    /// arguments and `output` buffers of equal length, they will get the
    /// same sequence of bytes in `output`. These bytes are cryptographically
    /// strong and pseudorandom, and are suitable for use as keying material.
    ///
    /// See [RFC5705](https://tools.ietf.org/html/rfc5705) for more information.
    #[inline]
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), quinn_proto::crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }

    /// Modifies the number of unidirectional streams that may be concurrently opened.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already
    /// open. Large `count`s increase both minimum and worst-case memory consumption.
    #[inline]
    pub fn set_max_concurrent_uni_streams(&self, count: VarInt) {
        self.inner.set_max_concurrent_uni_streams(count)
    }

    /// See [`quinn_proto::TransportConfig::receive_window`].
    #[inline]
    pub fn set_receive_window(&self, receive_window: VarInt) {
        self.inner.set_receive_window(receive_window)
    }

    /// Modifies the number of bidirectional streams that may be concurrently opened.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already
    /// open. Large `count`s increase both minimum and worst-case memory consumption.
    #[inline]
    pub fn set_max_concurrent_bi_streams(&self, count: VarInt) {
        self.inner.set_max_concurrent_bi_streams(count)
    }
}

/// Try send a message to the rtt-actor.
///
/// If we can't notify the actor that will impact performance a little, but we can still
/// function.
fn try_send_rtt_msg(conn: &quinn::Connection, ep: &Endpoint, remote_id: PublicKey) {
    let Some(conn_type_changes) = ep.conn_type(remote_id.into()) else {
        warn!(?conn, "failed to create conn_type stream");
        return;
    };
    let rtt_msg = RttMessage::NewConnection {
        connection: conn.weak_handle(),
        conn_type_changes: conn_type_changes.stream(),
        endpoint_id: remote_id,
    };
    if let Err(err) = ep.rtt_actor.msg_tx.try_send(rtt_msg) {
        warn!(?conn, "rtt-actor not reachable: {err:#}");
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::{EndpointAddr, SecretKey};
    use n0_error::{Result, StackResultExt, StdResultExt};
    use rand::SeedableRng;
    use tracing::{Instrument, info_span, trace_span};
    use tracing_test::traced_test;

    use super::Endpoint;
    use crate::{
        RelayMode,
        endpoint::{ConnectOptions, Incoming, ZeroRttStatus},
    };

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    async fn spawn_0rtt_server(secret_key: SecretKey, log_span: tracing::Span) -> Result<Endpoint> {
        let server = Endpoint::empty_builder(RelayMode::Disabled)
            .secret_key(secret_key)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .instrument(log_span.clone())
            .await?;

        async fn handle_incoming(incoming: Incoming) -> Result {
            let accepting = incoming
                .accept()
                .std_context("Failed to accept incoming connection")?;

            // accept a possible 0-RTT connection
            let zrtt_conn = accepting.into_0rtt();

            let (mut send, mut recv) = zrtt_conn
                .accept_bi()
                .await
                .std_context("failed to accept bi stream")?;

            let data = recv
                .read_to_end(10_000_000)
                .await
                .std_context("Failed to read data")?;

            send.write_all(&data)
                .await
                .std_context("Failed to write data")?;
            send.finish().std_context("Failed to finish send")?;

            // Stay alive until the other side closes the connection.
            zrtt_conn.closed().await;
            Ok(())
        }

        // Gets aborted via the endpoint closing causing an `Err`
        // a simple echo server
        tokio::spawn({
            let server = server.clone();
            async move {
                tracing::trace!("Server accept loop started");
                while let Some(incoming) = server.accept().await {
                    tracing::trace!("Server received incoming connection");
                    // Handle connection errors gracefully instead of exiting the task
                    if let Err(e) = handle_incoming(incoming).await {
                        tracing::warn!("Failure while handling connection: {e:#}");
                    }
                    tracing::trace!("Connection closed, ready for next");
                }
                tracing::trace!("Server accept loop exiting");
                n0_error::Ok(())
            }
            .instrument(log_span)
        });

        Ok(server)
    }

    async fn connect_client_0rtt_expect_err(
        client: &Endpoint,
        server_addr: EndpointAddr,
    ) -> Result {
        let conn = client
            .connect_with_opts(server_addr, TEST_ALPN, ConnectOptions::new())
            .await?
            .into_0rtt()
            .expect_err("expected 0-RTT to fail")
            .await?;

        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        send.write_all(b"hello").await.anyerr()?;
        send.finish().anyerr()?;
        let received = recv.read_to_end(1_000).await.anyerr()?;
        assert_eq!(&received, b"hello");
        conn.close(0u32.into(), b"thx");
        Ok(())
    }

    async fn connect_client_0rtt_expect_ok(
        client: &Endpoint,
        server_addr: EndpointAddr,
        expect_server_accepts: bool,
    ) -> Result {
        tracing::trace!(?server_addr, "Client connecting with 0-RTT");
        let zrtt_conn = client
            .connect_with_opts(server_addr, TEST_ALPN, ConnectOptions::new())
            .await
            .context("connect")?
            .into_0rtt()
            .ok()
            .context("into_0rtt")?;

        tracing::trace!("Client established 0-RTT connection");
        // This is how we send data in 0-RTT:
        let (mut send, mut recv) = zrtt_conn.open_bi().await.anyerr()?;
        send.write_all(b"hello").await.anyerr()?;
        send.finish().anyerr()?;
        tracing::trace!("Client sent 0-RTT data, waiting for server response");
        // When this resolves, we've gotten a response from the server about whether the 0-RTT data above was accepted:
        let zrtt_res = zrtt_conn.handshake_completed().await;
        tracing::trace!(?zrtt_res, "Server responded to 0-RTT");
        let zrtt_res = zrtt_res.context("handshake completed")?;
        let conn = match zrtt_res {
            ZeroRttStatus::Accepted(conn) => {
                assert!(expect_server_accepts);
                conn
            }
            ZeroRttStatus::Rejected(conn) => {
                assert!(!expect_server_accepts);
                // in this case we need to re-send data by re-creating the stream.
                let (mut send, r) = conn.open_bi().await.anyerr()?;
                send.write_all(b"hello").await.anyerr()?;
                send.finish().anyerr()?;
                recv = r;
                conn
            }
        };
        let received = recv.read_to_end(1_000).await.anyerr()?;
        assert_eq!(&received, b"hello");
        conn.close(0u32.into(), b"thx");
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_0rtt() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let client = Endpoint::empty_builder(RelayMode::Disabled).bind().await?;
        let server = spawn_0rtt_server(SecretKey::generate(&mut rng), info_span!("server")).await?;

        connect_client_0rtt_expect_err(&client, server.addr()).await?;
        // The second 0rtt attempt should work
        connect_client_0rtt_expect_ok(&client, server.addr(), true).await?;

        client.close().await;
        server.close().await;

        Ok(())
    }

    // We have this test, as this would've failed at some point.
    // This effectively tests that we correctly categorize the TLS session tickets we
    // receive into the respective "bucket" for the recipient.
    #[tokio::test]
    #[traced_test]
    async fn test_0rtt_non_consecutive() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let client = Endpoint::empty_builder(RelayMode::Disabled).bind().await?;
        let server = spawn_0rtt_server(SecretKey::generate(&mut rng), info_span!("server")).await?;

        connect_client_0rtt_expect_err(&client, server.addr()).await?;

        // connecting with another endpoint should not interfere with our
        // TLS session ticket cache for the first endpoint:
        let another =
            spawn_0rtt_server(SecretKey::generate(&mut rng), info_span!("another")).await?;
        connect_client_0rtt_expect_err(&client, another.addr()).await?;
        another.close().await;

        connect_client_0rtt_expect_ok(&client, server.addr(), true).await?;

        client.close().await;
        server.close().await;

        Ok(())
    }

    // Test whether 0-RTT is possible after a restart:
    #[tokio::test]
    #[traced_test]
    async fn test_0rtt_after_server_restart() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let client = Endpoint::empty_builder(RelayMode::Disabled)
            .bind()
            .instrument(info_span!("client"))
            .await?;
        let server_key = SecretKey::generate(&mut rng);
        let server = spawn_0rtt_server(server_key.clone(), info_span!("server-initial")).await?;

        connect_client_0rtt_expect_err(&client, server.addr())
            .instrument(trace_span!("connect1"))
            .await
            .context("client connect 1")?;
        connect_client_0rtt_expect_ok(&client, server.addr(), true)
            .instrument(trace_span!("connect2"))
            .await
            .context("client connect 2")?;

        // adds time to the test, but we need to ensure the server is fully closed before spawning the next one.
        server.close().await;

        let server = spawn_0rtt_server(server_key, info_span!("server-restart")).await?;

        // we expect the client to *believe* it can 0-RTT connect to the server (hence expect_ok),
        // but the server will reject the early data because it discarded necessary state
        // to decrypt it when restarting.
        connect_client_0rtt_expect_ok(&client, server.addr(), false)
            .instrument(trace_span!("connect3"))
            .await
            .context("client connect 3")?;

        tokio::join!(client.close(), server.close());
        Ok(())
    }
}
