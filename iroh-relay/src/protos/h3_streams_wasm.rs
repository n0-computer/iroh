//! Browser WebTransport stream adapter for the relay protocol.
//!
//! The browser counterpart to [`h3_streams`](super::h3_streams). It carries each
//! relay message on a fresh WebTransport unidirectional stream, exactly like the
//! native path, but over the browser's native WebTransport session
//! ([`web_transport_wasm::Session`]) instead of raw noq streams.
//!
//! Unlike the native adapter, this one does not write the WebTransport stream
//! header itself: the browser's WebTransport layer adds it when a uni stream is
//! opened and strips it on the receiving side, so we only ever see the payload.

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
    /// Create from an established browser WebTransport session.
    pub fn new(session: Session) -> Self {
        let recv_fut = Box::pin(recv_one_message(session.clone()));
        Self {
            session,
            pending_send: None,
            send_fut: None,
            recv_fut,
            recv_terminated: false,
            send_priority: 0,
        }
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

/// Accept a uni stream and read the payload to EOF. The browser has already
/// stripped the WebTransport stream header.
async fn recv_one_message(session: Session) -> Result<Bytes, StreamError> {
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

/// Open a uni stream, write the payload, and finish it. The browser adds the
/// WebTransport stream header.
async fn send_one_message(
    session: Session,
    priority: i32,
    payload: Bytes,
) -> Result<(), StreamError> {
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
                this.recv_fut = Box::pin(recv_one_message(this.session.clone()));
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
