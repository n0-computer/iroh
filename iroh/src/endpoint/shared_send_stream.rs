//! A [`SendStream`] that can have its affinity changed from other tasks.

use std::{
    pin::Pin,
    sync::{Arc, Mutex, Weak},
};

use n0_error::{e, stack_error};
use noq::{ClosedStream, SendStream, Stopped, StreamAffinity, StreamId, VarInt, WriteError};

/// A [`SendStream`] whose affinity can be changed from other tasks via [`AffinityHandle`]s.
///
/// One task writes to the stream, while any number of [`AffinityHandle`]s change its
/// affinity, for example from a task that watches [`Connection::path_events`].
///
/// Dropping a [`SharedSendStream`] finishes the stream, just like dropping a [`SendStream`].
/// Data that still needs to be retransmitted after that keeps the last affinity that was set.
/// Keep the [`SharedSendStream`] until [`SharedSendStream::stopped`] resolves if affinity
/// changes should apply until the peer has received everything.
///
/// [`Connection::path_events`]: crate::endpoint::Connection::path_events
#[derive(Debug)]
pub struct SharedSendStream {
    inner: Arc<Mutex<SendStream>>,
}

impl SharedSendStream {
    /// Wraps `send` so its affinity can be changed from other tasks.
    pub fn new(send: SendStream) -> Self {
        Self {
            inner: Arc::new(Mutex::new(send)),
        }
    }

    /// Returns a handle that changes this stream's affinity.
    pub fn affinity_handle(&self) -> AffinityHandle {
        AffinityHandle {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Writes bytes to the stream, returning how many were written.
    ///
    /// See [`SendStream::write`]. The stream is only locked while it is polled, so
    /// [`AffinityHandle::set`] can run while a write is waiting.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, WriteError> {
        std::future::poll_fn(|cx| {
            let mut send = self.inner.lock().expect("poisoned");
            Pin::new(&mut *send).poll_write(cx, buf)
        })
        .await
    }

    /// Writes all of `buf` to the stream.
    ///
    /// See [`SendStream::write_all`].
    pub async fn write_all(&self, mut buf: &[u8]) -> Result<(), WriteError> {
        while !buf.is_empty() {
            let written = self.write(buf).await?;
            buf = &buf[written..];
        }
        Ok(())
    }

    /// Finishes the stream.
    ///
    /// See [`SendStream::finish`].
    pub fn finish(&self) -> Result<(), ClosedStream> {
        self.inner.lock().expect("poisoned").finish()
    }

    /// Resets the stream.
    ///
    /// See [`SendStream::reset`].
    pub fn reset(&self, error_code: VarInt) -> Result<(), ClosedStream> {
        self.inner.lock().expect("poisoned").reset(error_code)
    }

    /// Completes when the peer stops the stream or has received all of its data.
    ///
    /// See [`SendStream::stopped`]. The returned future does not hold the stream locked.
    pub fn stopped(&self) -> Stopped {
        self.inner.lock().expect("poisoned").stopped()
    }

    /// Returns the id of the stream.
    pub fn id(&self) -> StreamId {
        self.inner.lock().expect("poisoned").id()
    }
}

/// A cloneable handle to change the affinity of a [`SharedSendStream`] from another task.
///
/// The handle does not keep the stream alive.
#[derive(Debug, Clone)]
pub struct AffinityHandle {
    inner: Weak<Mutex<SendStream>>,
}

impl AffinityHandle {
    /// Sets the affinity of the stream.
    ///
    /// See [`SendStream::set_affinity`].
    pub fn set(&self, affinity: StreamAffinity) -> Result<(), SetAffinityError> {
        let Some(inner) = self.inner.upgrade() else {
            return Err(e!(SetAffinityError::Dropped));
        };
        inner
            .lock()
            .expect("poisoned")
            .set_affinity(affinity)
            .map_err(|source| e!(SetAffinityError::Closed { source }))
    }
}

/// Error returned by [`AffinityHandle::set`].
#[stack_error(add_meta, derive)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum SetAffinityError {
    #[error("the shared send stream was dropped")]
    Dropped,
    #[error(transparent)]
    Closed {
        #[error(std_err)]
        source: ClosedStream,
    },
}
