//! Streams used in the server-side implementation of iroh relays.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use n0_future::{Sink, Stream};
use snafu::Snafu;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use tokio_websockets::WebSocketStream;

use crate::{
    protos::relay::{Frame, RelayCodec, RelayProtoError},
    KeyCache,
};

/// A Stream and Sink for [`Frame`]s connected to a single relay client.
///
/// The stream receives message from the client while the sink sends them to the client.
#[derive(Debug)]
pub(crate) enum RelayedStream {
    Relay(Framed<MaybeTlsStream, RelayCodec>),
    Ws(WebSocketStream<MaybeTlsStream>, KeyCache),
}

fn ws_to_io_err(e: tokio_websockets::Error) -> std::io::Error {
    match e {
        tokio_websockets::Error::Io(io_err) => io_err,
        _ => std::io::Error::other(e.to_string()),
    }
}

impl Sink<Frame> for RelayedStream {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match *self {
            Self::Relay(ref mut framed) => Pin::new(framed).poll_ready(cx),
            Self::Ws(ref mut ws, _) => Pin::new(ws).poll_ready(cx).map_err(ws_to_io_err),
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Frame) -> Result<(), Self::Error> {
        match *self {
            Self::Relay(ref mut framed) => Pin::new(framed).start_send(item),
            Self::Ws(ref mut ws, _) => Pin::new(ws)
                .start_send(tokio_websockets::Message::binary(
                    tokio_websockets::Payload::from(item.encode_for_ws_msg()),
                ))
                .map_err(ws_to_io_err),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match *self {
            Self::Relay(ref mut framed) => Pin::new(framed).poll_flush(cx),
            Self::Ws(ref mut ws, _) => Pin::new(ws).poll_flush(cx).map_err(ws_to_io_err),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match *self {
            Self::Relay(ref mut framed) => Pin::new(framed).poll_close(cx),
            Self::Ws(ref mut ws, _) => Pin::new(ws).poll_close(cx).map_err(ws_to_io_err),
        }
    }
}

/// Relay stream errors
#[derive(Debug, Snafu)]
pub enum StreamError {
    #[snafu(transparent)]
    Proto { source: RelayProtoError },
    #[snafu(transparent)]
    Ws { source: tokio_websockets::Error },
}

impl Stream for RelayedStream {
    type Item = Result<Frame, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match *self {
            Self::Relay(ref mut framed) => Pin::new(framed).poll_next(cx).map_err(Into::into),
            Self::Ws(ref mut ws, ref cache) => match Pin::new(ws).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    if msg.is_close() {
                        // Indicate the stream is done when we receive a close message.
                        // Note: We don't have to poll the stream to completion for it to close gracefully.
                        return Poll::Ready(None);
                    }
                    if !msg.is_binary() {
                        tracing::warn!(
                            ?msg,
                            "Got websocket message of unsupported type, skipping."
                        );
                        return Poll::Pending;
                    }
                    let frame = Frame::decode_from_ws_msg(msg.into_payload().into(), cache)
                        .map_err(Into::into);
                    Poll::Ready(Some(frame))
                }
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

/// The main underlying IO stream type used for the relay server.
///
/// Allows choosing whether or not the underlying [`tokio::net::TcpStream`] is served over Tls
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeTlsStream {
    /// A plain non-Tls [`tokio::net::TcpStream`]
    Plain(tokio::net::TcpStream),
    /// A Tls wrapped [`tokio::net::TcpStream`]
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
    /// An in-memory bidirectional pipe.
    #[cfg(test)]
    Test(tokio::io::DuplexStream),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_flush(cx),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_write_vectored(cx, bufs),
            MaybeTlsStream::Tls(ref mut s) => Pin::new(s).poll_write_vectored(cx, bufs),
            #[cfg(test)]
            MaybeTlsStream::Test(ref mut s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }
}
