//! Utilities used in [`iroh`][`crate`]

use pin_project::pin_project;
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
#[pin_project(project = MaybeFutureProj, project_replace = MaybeFutureProjReplace)]
pub(crate) enum MaybeFuture<T> {
    /// Future to be polled.
    Some(#[pin] T),
    None,
}

impl<T> MaybeFuture<T> {
    /// Creates a [`MaybeFuture`] without an inner future.
    pub(crate) fn none() -> Self {
        Self::None
    }

    /// Clears the value
    pub(crate) fn set_none(mut self: Pin<&mut Self>) {
        self.as_mut().project_replace(Self::None);
    }

    /// Sets a new future.
    pub(crate) fn set_future(mut self: Pin<&mut Self>, fut: T) {
        self.as_mut().project_replace(Self::Some(fut));
    }

    /// Returns `true` if the inner is empty.
    pub(crate) fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns `true` if the inner contains a future.
    pub(crate) fn is_some(&self) -> bool {
        matches!(self, Self::Some(_))
    }
}

// NOTE: explicit implementation to bypass derive unnecessary bounds
impl<T> Default for MaybeFuture<T> {
    fn default() -> Self {
        Self::none()
    }
}

impl<T: Future> Future for MaybeFuture<T> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this {
            MaybeFutureProj::Some(t) => t.poll(cx),
            MaybeFutureProj::None => Poll::Pending,
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
