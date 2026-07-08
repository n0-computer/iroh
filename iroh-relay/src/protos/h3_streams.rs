//! WebTransport stream adapter for the relay protocol.
//!
//! [`WtBytesFramed`] carries each relay message either on a new unidirectional
//! QUIC stream (the default) or as a single QUIC datagram, selected at runtime
//! by the `use_datagrams` flag negotiated in the CONNECT handshake.
//!
//! In uni-stream mode each stream carries the standard WebTransport uni-stream
//! header `[StreamUni::WEBTRANSPORT][session_id]` followed by the payload and is
//! finished, so the receiver reads to EOF; successive send streams get
//! increasing priority so the QUIC scheduler prefers newer messages over
//! retransmissions of older ones. In datagram mode the payload is the whole
//! message; datagrams are unreliable and capped at the connection's path MTU, so
//! an over-large one is dropped (iroh's own QUIC over the relay retransmits it).
//!
//! [`BytesStreamSink`]: super::streams::BytesStreamSink

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use n0_error::{StdResultExt, anyerr};
use n0_future::{Sink, Stream, ready};
use tokio::io::AsyncReadExt;
use tokio_util::sync::ReusableBoxFuture;
use tracing::trace;
use web_transport_proto as wt;

use super::streams::StreamError;
use crate::ExportKeyingMaterial;

/// Maximum bytes to read from a single uni stream before rejecting.
const MAX_UNI_STREAM_SIZE: usize = crate::MAX_PACKET_SIZE + 64;

/// Relay transport using one unidirectional QUIC stream per message.
///
/// Each message is sent on a fresh uni stream with a WT session header and
/// the raw payload. The receiver accepts uni streams and reads each to EOF.
/// This eliminates head-of-line blocking: retransmission on one stream does
/// not delay delivery of later messages on other streams.
pub struct WtBytesFramed {
    conn: noq::Connection,
    /// Precomputed WebTransport uni-stream header for this session, cloned per
    /// send. Unused in datagram mode.
    header: Bytes,
    /// Carry messages as QUIC datagrams instead of uni streams. Both ends agree
    /// on this via the CONNECT handshake, so the receiver reads the same framing.
    use_datagrams: bool,
    pending_send: Option<Bytes>,
    send_fut: ReusableBoxFuture<'static, Result<(), StreamError>>,
    recv_fut: ReusableBoxFuture<'static, Result<Bytes, StreamError>>,
    recv_terminated: bool,
    send_busy: bool,
    send_priority: i32,
}

impl std::fmt::Debug for WtBytesFramed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WtBytesFramed").finish()
    }
}

impl WtBytesFramed {
    /// Create from a QUIC connection, the WebTransport session ID, and the
    /// negotiated framing (`use_datagrams`).
    pub fn new(conn: noq::Connection, session_id: u64, use_datagrams: bool) -> Self {
        let recv_conn = conn.clone();
        Self {
            conn,
            header: encode_wt_header(session_id).freeze(),
            use_datagrams,
            pending_send: None,
            send_fut: ReusableBoxFuture::new(std::future::pending()),
            recv_fut: ReusableBoxFuture::new(recv_one_message(recv_conn, use_datagrams)),
            recv_terminated: false,
            send_busy: false,
            send_priority: 0,
        }
    }
}

/// Encode the WebTransport unidirectional stream header for the given session ID.
///
/// This is the standard WebTransport uni-stream framing: the
/// [`StreamUni::WEBTRANSPORT`](wt::StreamUni::WEBTRANSPORT) stream type followed
/// by the session ID. A real browser writes exactly this header in front of
/// every uni stream it opens, and only recognises incoming uni streams that
/// carry it, so the server must use it too for browser interop.
fn encode_wt_header(session_id: u64) -> BytesMut {
    let mut hdr = BytesMut::with_capacity(16);
    wt::StreamUni::WEBTRANSPORT.encode(&mut hdr);
    wt::VarInt::from_u64(session_id)
        .expect("session ID fits in varint")
        .encode(&mut hdr);
    hdr
}

impl ExportKeyingMaterial for WtBytesFramed {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        mut output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        self.conn
            .export_keying_material(output.as_mut(), label, context.unwrap_or(&[]))
            .ok()?;
        Some(output)
    }
}

impl ExportKeyingMaterial for noq::Connection {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        mut output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        noq::Connection::export_keying_material(
            self,
            output.as_mut(),
            label,
            context.unwrap_or(&[]),
        )
        .ok()?;
        Some(output)
    }
}

/// Accept a WebTransport uni stream, skip its header, and read the payload.
///
/// Each relay message arrives on its own uni stream prefixed with the
/// [`StreamUni::WEBTRANSPORT`](wt::StreamUni::WEBTRANSPORT) type and the session
/// ID (see [`encode_wt_header`]). A real browser also opens HTTP/3 control and
/// QPACK unidirectional streams on the same connection; those are drained and
/// kept alive in the background so their (critical) streams are not reset, and
/// we keep accepting until an actual WebTransport stream arrives.
async fn recv_one_message(
    conn: noq::Connection,
    use_datagrams: bool,
) -> Result<Bytes, StreamError> {
    if use_datagrams {
        return conn.read_datagram().await.anyerr();
    }
    loop {
        let recv = conn.accept_uni().await.anyerr()?;
        let mut recv = tokio::io::BufReader::new(recv);
        let stream_type = wt::VarInt::read(&mut recv).await.anyerr()?;
        if stream_type != wt::StreamUni::WEBTRANSPORT.0 {
            // An HTTP/3 control or QPACK unidirectional stream (a real browser
            // opens these). Ignore its contents but keep it alive: dropping the
            // receive stream would reset a critical H3 stream and abort the
            // browser's session.
            trace!(stream_type = %stream_type, "ignoring non-WebTransport uni stream");
            drain_in_background(recv);
            continue;
        }
        // Skip the session ID; we serve a single WebTransport session per
        // connection, so there is nothing to demultiplex.
        let _session_id = wt::VarInt::read(&mut recv).await.anyerr()?;
        let mut payload = Vec::new();
        recv.take(MAX_UNI_STREAM_SIZE as u64 + 1)
            .read_to_end(&mut payload)
            .await
            .anyerr()?;
        if payload.len() > MAX_UNI_STREAM_SIZE {
            return Err(anyerr!("uni stream exceeds max size"));
        }
        return Ok(Bytes::from(payload));
    }
}

/// Read and discard the rest of a receive stream in a detached task, holding it
/// open until it finishes or the connection closes.
///
/// Shared with the H3 server, which drains the browser's HTTP/3 control and
/// QPACK uni streams the same way.
pub(crate) fn drain_in_background<R>(mut reader: R)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::task::spawn(async move {
        let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
    });
}

/// Send one relay message: a fresh uni stream (WT header + payload, then
/// finished), or a single QUIC datagram when `use_datagrams` is set.
///
/// `header` is the per-connection WebTransport uni-stream header, precomputed
/// once (see [`WtBytesFramed::new`]) and cheaply cloned per message; it is
/// unused in datagram mode.
///
/// Datagrams are unreliable by design, and a relayed iroh packet plus framing
/// can exceed the WebTransport connection's max datagram size on a small-MTU
/// path. A `TooLarge` datagram is therefore dropped -- iroh's own QUIC
/// connection running over the relay retransmits it and its PLPMTUD backs off --
/// rather than surfaced as a fatal error that would tear the relay connection
/// down and reconnect.
async fn send_one_message(
    conn: noq::Connection,
    header: Bytes,
    priority: i32,
    payload: Bytes,
    use_datagrams: bool,
) -> Result<(), StreamError> {
    if use_datagrams {
        return match conn.send_datagram(payload) {
            Ok(()) => Ok(()),
            Err(noq::SendDatagramError::TooLarge) => {
                trace!("dropping too-large relay datagram; iroh QUIC will retransmit");
                Ok(())
            }
            Err(err) => Err(anyerr!(err)),
        };
    }
    let mut stream = conn.open_uni().await.anyerr()?;
    let _ = stream.set_priority(priority);
    // Write the WT header and payload in one batched, zero-copy call.
    let mut chunks = [header, payload];
    stream.write_all_chunks(&mut chunks).await.anyerr()?;
    stream.finish().anyerr()?;
    Ok(())
}

// -- Stream: accept uni streams, read each to EOF -----------------------------

impl Stream for WtBytesFramed {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.recv_terminated {
            return Poll::Ready(None);
        }

        match ready!(this.recv_fut.poll(cx)) {
            Ok(payload) => {
                // Immediately set up the next recv.
                let conn = this.conn.clone();
                this.recv_fut
                    .set(recv_one_message(conn, this.use_datagrams));
                // The relay protocol never frames an empty message, so an empty
                // payload is malformed. Yield it and let the frame decoder reject
                // it; returning `Pending` here would strand the stream, since the
                // freshly armed `recv_fut` has not been polled to register a waker.
                Poll::Ready(Some(Ok(payload)))
            }
            Err(e) => {
                // Connection closed or error. The recv future has completed and
                // is deliberately not re-armed; fuse the stream so a later poll
                // returns `None` instead of re-polling a finished future.
                this.recv_terminated = true;
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}

// -- Sink: new uni stream per message -----------------------------------------

impl Sink<Bytes> for WtBytesFramed {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        // Flush in-progress send.
        if this.send_busy {
            match ready!(this.send_fut.poll(cx)) {
                Ok(()) => {
                    this.send_busy = false;
                }
                Err(e) => {
                    this.send_busy = false;
                    return Poll::Ready(Err(e));
                }
            }
        }

        // Start sending a pending message.
        if let Some(msg) = this.pending_send.take() {
            let conn = this.conn.clone();
            let header = this.header.clone();
            let priority = this.send_priority;
            let use_datagrams = this.use_datagrams;
            this.send_priority = this.send_priority.saturating_add(1);
            this.send_fut
                .set(send_one_message(conn, header, priority, msg, use_datagrams));
            this.send_busy = true;
            let pin = Pin::new(this);
            return pin.poll_ready(cx);
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
