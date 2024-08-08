use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_lite::Stream;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

/// Wrapper around [`Stream`] that takes a cancel token to cancel the stream.
///
/// Once the cancel token is cancelled, this stream will continue to yield all items which are
/// ready immediately and then return [`None`].
#[derive(Debug)]
pub struct Cancelable<S> {
    stream: S,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    is_cancelled: bool,
}

impl<S> Cancelable<S> {
    pub fn new(stream: S, cancel_token: CancellationToken) -> Self {
        Self {
            stream,
            cancelled: Box::pin(cancel_token.cancelled_owned()),
            is_cancelled: false,
        }
    }
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Stream + Unpin> Stream for Cancelable<S> {
    type Item = S::Item;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.stream).poll_next(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => {
                if self.is_cancelled {
                    return Poll::Ready(None);
                }
                match Pin::new(&mut self.cancelled).poll(cx) {
                    Poll::Ready(()) => {
                        self.is_cancelled = true;
                        Poll::Ready(None)
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}
