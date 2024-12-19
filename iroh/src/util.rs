//! Utilities used in [`iroh`][`crate`]

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project::pin_project;

/// A future which may not be present.
///
/// This is a single type which may optionally contain a future.  If there is no inner
/// future polling will always return [`Poll::Pending`].
///
/// The [`Default`] impl will create a [`MaybeFuture`] without an inner.
#[derive(Default, Debug)]
#[pin_project(project = MaybeFutureProj, project_replace = MaybeFutureProjReplace)]
pub(crate) enum MaybeFuture<T> {
    /// Future to be polled.
    Some(#[pin] T),
    #[default]
    None,
}

impl<T> MaybeFuture<T> {
    /// Creates a [`MaybeFuture`] without an inner future.
    pub(crate) fn none() -> Self {
        Self::default()
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
