//! Utilities used in [`iroh`][`crate`]

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Resolves to pending if the inner is `None`.
#[derive(Debug)]
pub(crate) struct MaybeFuture<T> {
    /// Future to be polled.
    pub inner: Option<T>,
}

// NOTE: explicit implementation to bypass derive unnecessary bounds
impl<T> Default for MaybeFuture<T> {
    fn default() -> Self {
        MaybeFuture { inner: None }
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

/// Check if we are running in "relay only" mode, as informed
/// by the compile time env var `DEV_RELAY_ONLY`.
///
/// "relay only" mode implies we only use the relay to communicate
/// and do not attempt to do any hole punching.
pub(crate) fn relay_only_mode() -> bool {
    std::option_env!("DEV_RELAY_ONLY").is_some()
}
