//! Utilities used in [`iroh`][`crate`]

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// A future which may not be present.
///
/// This is a single type which may optionally contain a future.  If there is no inner
/// future polling will always return [`Poll::Pending`].
///
/// The [`Default`] impl will create a [`MaybeFuture`] without an inner.
#[derive(Debug)]
pub(crate) struct MaybeFuture<T> {
    /// Future to be polled.
    pub inner: Option<T>,
}

impl<T> MaybeFuture<T> {
    /// Creates a [`MaybeFuture`] without an inner future.
    pub(crate) fn none() -> Self {
        Self { inner: None }
    }

    /// Creates a [`MaybeFuture`] with an inner future.
    pub(crate) fn with_future(fut: T) -> Self {
        Self { inner: Some(fut) }
    }

    /// Returns `true` if the inner is empty.
    pub(crate) fn is_none(&self) -> bool {
        self.inner.is_none()
    }

    /// Returns `true` if the inner contains a future.
    pub(crate) fn is_some(&self) -> bool {
        self.inner.is_some()
    }
}

// NOTE: explicit implementation to bypass derive unnecessary bounds
impl<T> Default for MaybeFuture<T> {
    fn default() -> Self {
        Self::none()
    }
}

impl<T: Future + Unpin> Future for MaybeFuture<T> {
    type Output = T::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner {
            Some(ref mut t) => Pin::new(t).poll(cx),
            None => Poll::Pending,
        }
    }
}
