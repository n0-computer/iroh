//! WebTransport stream adapter for the relay protocol.
//!
//! [`WtBytesFramed`] wraps a noq bidirectional QUIC stream (opened within a
//! WebTransport session) into a [`BytesStreamSink`]-compatible type. Messages
//! are length-prefixed with QUIC varints for browser compatibility.
//!
//! [`BytesStreamSink`]: super::streams::BytesStreamSink

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use n0_future::{Sink, Stream, ready};
use noq::VarInt;
use noq_proto::coding::{Decodable, Encodable};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::streams::StreamError;
use crate::ExportKeyingMaterial;

/// Relay transport backed by a WebTransport bidirectional stream.
///
/// Messages are framed as `[varint length][payload]` using QUIC variable-length
/// integers. This framing is compatible with browser WebTransport clients that
/// open bidi streams via `createBidirectionalStream()`.
pub struct WtBytesFramed {
    send: noq::SendStream,
    recv: noq::RecvStream,
    /// QUIC connection handle for TLS keying material export.
    conn: noq::Connection,
    recv_buf: BytesMut,
    send_buf: BytesMut,
}

impl std::fmt::Debug for WtBytesFramed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WtBytesFramed").finish()
    }
}

impl WtBytesFramed {
    /// Create from a noq bidirectional stream pair and the parent connection.
    ///
    /// The connection handle is used for TLS keying material export during the
    /// relay handshake, avoiding an extra authentication round-trip.
    pub fn new(send: noq::SendStream, recv: noq::RecvStream, conn: noq::Connection) -> Self {
        Self {
            send,
            recv,
            conn,
            recv_buf: BytesMut::with_capacity(4096),
            send_buf: BytesMut::new(),
        }
    }
}

impl ExportKeyingMaterial for WtBytesFramed {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        mut output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        let buf = output.as_mut();
        self.conn
            .export_keying_material(buf, label, context.unwrap_or(&[]))
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

/// Try to decode a varint from the front of `buf` without advancing the buffer.
///
/// Returns `Some((value, header_len))` if enough bytes are present to decode a
/// complete varint. Returns `None` if the buffer is too short.
fn try_decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut cursor = buf;
    let before = cursor.len();
    let val = VarInt::decode(&mut cursor).ok()?;
    let consumed = before - cursor.len();
    Some((val.into_inner(), consumed))
}

// -- Stream: read varint-length-prefixed messages -------------------------

impl Stream for WtBytesFramed {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // Try to parse a complete message from the buffer.
            if let Some((message_len, header_len)) = try_decode_varint(&this.recv_buf) {
                let total = header_len + message_len as usize;
                if this.recv_buf.len() >= total {
                    this.recv_buf.advance(header_len);
                    let payload = this.recv_buf.split_to(message_len as usize).freeze();
                    return Poll::Ready(Some(Ok(payload)));
                }
            }

            // Read more data from the QUIC stream into recv_buf.
            let mut tmp = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut tmp);
            match ready!(Pin::new(&mut this.recv).poll_read(cx, &mut read_buf)) {
                Ok(()) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if this.recv_buf.is_empty() {
                            return Poll::Ready(None);
                        }
                        return Poll::Ready(Some(Err(StreamError::new(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "stream ended mid-message",
                        )))));
                    }
                    this.recv_buf.extend_from_slice(&tmp[..n]);
                }
                Err(e) => return Poll::Ready(Some(Err(StreamError::new(e)))),
            }
        }
    }
}

// -- Sink: write varint-length-prefixed messages --------------------------

impl Sink<Bytes> for WtBytesFramed {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        while !this.send_buf.is_empty() {
            match ready!(Pin::new(&mut this.send).poll_write(cx, &this.send_buf)) {
                Ok(n) => {
                    this.send_buf.advance(n);
                }
                Err(e) => return Poll::Ready(Err(StreamError::new(e))),
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let len = VarInt::from_u64(item.len() as u64).map_err(|_| {
            StreamError::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message too large for varint framing",
            ))
        })?;
        len.encode(&mut this.send_buf);
        this.send_buf.put_slice(&item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        while !this.send_buf.is_empty() {
            match ready!(Pin::new(&mut this.send).poll_write(cx, &this.send_buf)) {
                Ok(n) => {
                    this.send_buf.advance(n);
                }
                Err(e) => return Poll::Ready(Err(StreamError::new(e))),
            }
        }
        Pin::new(&mut this.send)
            .poll_flush(cx)
            .map_err(StreamError::new)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        while !this.send_buf.is_empty() {
            match ready!(Pin::new(&mut this.send).poll_write(cx, &this.send_buf)) {
                Ok(n) => {
                    this.send_buf.advance(n);
                }
                Err(e) => return Poll::Ready(Err(StreamError::new(e))),
            }
        }
        Pin::new(&mut this.send)
            .poll_shutdown(cx)
            .map_err(StreamError::new)
    }
}
