//! Generic utilities to track progress of data transfers.
//!
//! Based on your environment there might also be better choices for this, e.g. very
//! similar and more advanced functionality is available in the `indicatif` crate for
//! terminal applications.

use std::{pin::Pin, task::Poll};

use iroh_blobs::util::io::TrackingWriter;
use tokio::{
    io::{self, AsyncWrite},
    sync::mpsc,
};

/// A writer that tries to send the total number of bytes written after each write
///
/// It sends the total number instead of just an increment so the update is self-contained
#[derive(Debug)]
pub struct ProgressWriter<W> {
    inner: TrackingWriter<W>,
    sender: mpsc::Sender<u64>,
}

impl<W> ProgressWriter<W> {
    /// Create a new `ProgressWriter` from an inner writer
    pub fn new(inner: W) -> (Self, mpsc::Receiver<u64>) {
        let (sender, receiver) = mpsc::channel(1);
        (
            Self {
                inner: TrackingWriter::new(inner),
                sender,
            },
            receiver,
        )
    }

    /// Return the inner writer
    pub fn into_inner(self) -> W {
        self.inner.into_parts().0
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ProgressWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(_)) = res {
            this.sender.try_send(this.inner.bytes_written()).ok();
        }
        res
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
