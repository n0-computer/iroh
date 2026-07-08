//! Browser WebTransport stream adapter for the relay protocol.
//!
//! The browser counterpart to [`h3_streams`](super::h3_streams). It carries each
//! relay message either on a fresh WebTransport unidirectional stream (the
//! default) or as a single WebTransport datagram, selected at runtime by the
//! `use_datagrams` flag negotiated in the CONNECT handshake, exactly like the
//! native path, but over the browser's native WebTransport session
//! ([`web_transport_wasm::Session`]) instead of raw noq streams.
//!
//! Unlike the native adapter, this one does not write the WebTransport stream
//! header or datagram Quarter-Stream-ID prefix itself: the browser's
//! WebTransport layer adds it when a uni stream or datagram is sent and strips it
//! on the receiving side, so we only ever see the payload.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use n0_error::anyerr;
use n0_future::{Sink, Stream, ready};
use web_transport_wasm::Session;

use super::streams::StreamError;
use crate::{ExportKeyingMaterial, MAX_PACKET_SIZE};

/// Maximum bytes to read from a single uni stream before rejecting.
const MAX_UNI_STREAM_SIZE: usize = MAX_PACKET_SIZE + 64;

type LocalFut<T> = Pin<Box<dyn Future<Output = T>>>;

fn stream_err(err: web_transport_wasm::Error) -> StreamError {
    anyerr!("webtransport stream error: {err}")
}

/// Relay transport over the browser's WebTransport session, one uni stream per
/// message.
pub struct WtBytesFramed {
    session: Session,
    /// Carry messages as WebTransport datagrams instead of uni streams. Both
    /// ends agree on this via the CONNECT handshake, so the receiver reads the
    /// same framing.
    use_datagrams: bool,
    pending_send: Option<Bytes>,
    send_fut: Option<LocalFut<Result<(), StreamError>>>,
    recv_fut: LocalFut<Result<Bytes, StreamError>>,
    recv_terminated: bool,
    send_priority: i32,
}

impl std::fmt::Debug for WtBytesFramed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WtBytesFramed").finish()
    }
}

impl WtBytesFramed {
    /// Create from an established browser WebTransport session and the negotiated
    /// framing (`use_datagrams`).
    pub fn new(session: Session, use_datagrams: bool) -> Self {
        let recv_fut = Box::pin(recv_one_message(session.clone(), use_datagrams));
        Self {
            session,
            use_datagrams,
            pending_send: None,
            send_fut: None,
            recv_fut,
            recv_terminated: false,
            send_priority: 0,
        }
    }

    /// Whether this transport carries relay messages as WebTransport datagrams
    /// (rather than unidirectional streams).
    pub fn uses_datagrams(&self) -> bool {
        self.use_datagrams
    }

    /// Switch the framing between uni streams and datagrams.
    ///
    /// The handshake always runs over uni streams (the browser drops datagrams
    /// the server sends before the WebTransport session is fully established, so
    /// the relay challenge would be lost), so both ends construct the transport
    /// in uni mode and call this to switch to the negotiated framing before the
    /// data phase. Re-arms the pending receive with the new framing so the next
    /// message is read the same way it is sent.
    pub fn set_use_datagrams(&mut self, use_datagrams: bool) {
        self.use_datagrams = use_datagrams;
        self.recv_fut = Box::pin(recv_one_message(self.session.clone(), use_datagrams));
    }
}

impl ExportKeyingMaterial for WtBytesFramed {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        _output: T,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Option<T> {
        // The browser WebTransport API does not expose TLS keying material, so
        // the relay handshake falls back to the challenge-response mechanism.
        None
    }
}

/// Receive one relay message: a single WebTransport datagram when
/// `use_datagrams` is set, otherwise a uni stream read to EOF. The browser has
/// already stripped the WebTransport stream header or datagram prefix, so we see
/// only the payload.
async fn recv_one_message(session: Session, use_datagrams: bool) -> Result<Bytes, StreamError> {
    if use_datagrams {
        return session.recv_datagram().await.map_err(stream_err);
    }
    let mut recv = session.accept_uni().await.map_err(stream_err)?;
    let mut out = BytesMut::new();
    while let Some(chunk) = recv.read(MAX_UNI_STREAM_SIZE).await.map_err(stream_err)? {
        out.extend_from_slice(&chunk);
        if out.len() > MAX_UNI_STREAM_SIZE {
            return Err(anyerr!("uni stream exceeds max size"));
        }
    }
    Ok(out.freeze())
}

/// Send one relay message: a single WebTransport datagram when `use_datagrams`
/// is set, otherwise a fresh uni stream (payload, then finished). The browser
/// adds the WebTransport stream header or datagram prefix.
///
/// Datagrams are unreliable and browsers silently drop an over-size one per the
/// WebTransport spec (`web-transport-wasm`'s `Error` has no `TooLarge` variant),
/// so any surfaced error is simply propagated; iroh's own QUIC over the relay
/// retransmits a dropped packet.
async fn send_one_message(
    session: Session,
    priority: i32,
    payload: Bytes,
    use_datagrams: bool,
) -> Result<(), StreamError> {
    if use_datagrams {
        return session.send_datagram(payload).await.map_err(stream_err);
    }
    let mut stream = session.open_uni().await.map_err(stream_err)?;
    stream.set_priority(priority);
    stream.write(&payload).await.map_err(stream_err)?;
    stream.finish().map_err(stream_err)?;
    Ok(())
}

impl Stream for WtBytesFramed {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.recv_terminated {
            return Poll::Ready(None);
        }
        match ready!(this.recv_fut.as_mut().poll(cx)) {
            Ok(payload) => {
                this.recv_fut =
                    Box::pin(recv_one_message(this.session.clone(), this.use_datagrams));
                Poll::Ready(Some(Ok(payload)))
            }
            Err(e) => {
                // The recv future has completed and is deliberately not re-armed.
                // Fuse the stream so a subsequent poll returns `None` instead of
                // re-polling a finished future, which would panic.
                this.recv_terminated = true;
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}

impl Sink<Bytes> for WtBytesFramed {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        if let Some(fut) = this.send_fut.as_mut() {
            match ready!(fut.as_mut().poll(cx)) {
                Ok(()) => this.send_fut = None,
                Err(e) => {
                    this.send_fut = None;
                    return Poll::Ready(Err(e));
                }
            }
        }

        if let Some(msg) = this.pending_send.take() {
            let priority = this.send_priority;
            this.send_priority = this.send_priority.saturating_add(1);
            this.send_fut = Some(Box::pin(send_one_message(
                this.session.clone(),
                priority,
                msg,
                this.use_datagrams,
            )));
            return Pin::new(this).poll_ready(cx);
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.get_mut().pending_send = Some(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_ready(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_ready(cx)?);
        Poll::Ready(Ok(()))
    }
}
