//! WebTransport stream adapter for the relay protocol.
//!
//! [`WtBytesFramed`] uses a new unidirectional QUIC stream per relay message.
//! Each stream carries `[Frame::WEBTRANSPORT][session_id][payload]`. The stream
//! is finished after the payload, so the receiver reads to EOF. Successive send
//! streams get increasing priority so the QUIC scheduler prefers newer messages
//! over retransmissions of older ones.
//!
//! [`BytesStreamSink`]: super::streams::BytesStreamSink

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use n0_future::{Sink, Stream, ready};
use tokio_util::sync::ReusableBoxFuture;
use web_transport_proto as wt;

use super::streams::StreamError;
use crate::{ExportKeyingMaterial, MAX_PACKET_SIZE};

/// Maximum bytes to read from a single uni stream before rejecting.
const MAX_UNI_STREAM_SIZE: usize = MAX_PACKET_SIZE + 64;

fn io_err(e: impl std::fmt::Display) -> StreamError {
    StreamError::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
    ))
}

/// Relay transport using one unidirectional QUIC stream per message.
///
/// Each message is sent on a fresh uni stream with a WT session header and
/// the raw payload. The receiver accepts uni streams and reads each to EOF.
/// This eliminates head-of-line blocking: retransmission on one stream does
/// not delay delivery of later messages on other streams.
pub struct WtBytesFramed {
    conn: noq::Connection,
    session_id: u64,
    pending_send: Option<Bytes>,
    send_fut: ReusableBoxFuture<'static, Result<(), StreamError>>,
    recv_fut: ReusableBoxFuture<'static, Result<Bytes, StreamError>>,
    send_busy: bool,
    send_priority: i32,
}

impl std::fmt::Debug for WtBytesFramed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WtBytesFramed").finish()
    }
}

impl WtBytesFramed {
    /// Create from a QUIC connection and the WebTransport session ID.
    pub fn new(conn: noq::Connection, session_id: u64) -> Self {
        let recv_conn = conn.clone();
        let hdr_len = wt_header_len(session_id);
        Self {
            conn,
            session_id,
            pending_send: None,
            send_fut: ReusableBoxFuture::new(std::future::pending()),
            recv_fut: ReusableBoxFuture::new(recv_one_message(recv_conn, hdr_len)),
            send_busy: false,
            send_priority: 0,
        }
    }
}

/// Encode the WT uni stream header for the given session ID.
fn encode_wt_header(session_id: u64) -> BytesMut {
    let mut hdr = BytesMut::with_capacity(16);
    wt::Frame::WEBTRANSPORT.encode(&mut hdr);
    wt::VarInt::from_u64(session_id)
        .expect("session ID fits in varint")
        .encode(&mut hdr);
    hdr
}

fn wt_header_len(session_id: u64) -> usize {
    encode_wt_header(session_id).len()
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

/// Accept a uni stream, skip the WT header, read the payload to EOF.
async fn recv_one_message(
    conn: noq::Connection,
    wt_header_len: usize,
) -> Result<Bytes, StreamError> {
    let mut recv = conn.accept_uni().await.map_err(io_err)?;
    let data = recv
        .read_to_end(MAX_UNI_STREAM_SIZE)
        .await
        .map_err(io_err)?;
    if data.len() < wt_header_len {
        return Err(StreamError::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "uni stream shorter than WT header",
        )));
    }
    Ok(Bytes::from(data).slice(wt_header_len..))
}

/// Open a uni stream, write WT header and payload, finish the stream.
async fn send_one_message(
    conn: noq::Connection,
    session_id: u64,
    priority: i32,
    payload: Bytes,
) -> Result<(), StreamError> {
    let mut stream = conn.open_uni().await.map_err(io_err)?;
    let _ = stream.set_priority(priority);
    stream
        .write_chunk(encode_wt_header(session_id).freeze())
        .await
        .map_err(io_err)?;
    stream.write_chunk(payload).await.map_err(io_err)?;
    stream.finish().map_err(io_err)?;
    Ok(())
}

// -- Stream: accept uni streams, read each to EOF -----------------------------

impl Stream for WtBytesFramed {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        match ready!(this.recv_fut.poll(cx)) {
            Ok(payload) => {
                // Immediately set up the next recv.
                let conn = this.conn.clone();
                let hdr_len = wt_header_len(this.session_id);
                this.recv_fut.set(recv_one_message(conn, hdr_len));
                if payload.is_empty() {
                    Poll::Pending
                } else {
                    Poll::Ready(Some(Ok(payload)))
                }
            }
            Err(e) => {
                // Connection closed or error. Don't set up a new recv.
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
            let session_id = this.session_id;
            let priority = this.send_priority;
            this.send_priority = this.send_priority.saturating_add(1);
            this.send_fut
                .set(send_one_message(conn, session_id, priority, msg));
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
