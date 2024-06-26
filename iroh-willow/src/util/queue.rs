//! A simple asynchronous queue.

use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Poll, Waker},
};

use futures_lite::Stream;

/// A simple unbounded FIFO queue.
///
/// Values are pushed into the queue, synchronously.
/// The queue can be polled for the next value asynchronously.
#[derive(Debug)]
pub struct Queue<T> {
    items: VecDeque<T>,
    wakers: VecDeque<Waker>,
}

impl<T> Default for Queue<T> {
    fn default() -> Self {
        Self {
            items: Default::default(),
            wakers: Default::default(),
        }
    }
}

impl<T> Queue<T> {
    /// Push a new item to the back of the queue.
    pub fn push_back(&mut self, pair: T) {
        self.items.push_back(pair);
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }

    /// Attempt to pop the next item from the front of the queue.
    ///
    /// Returns [`Poll::Pending`] if no items are currently in the queue.
    pub fn poll_pop_front(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Option<T>> {
        if let Some(item) = self.items.pop_front() {
            Poll::Ready(Some(item))
        } else {
            self.wakers.push_back(cx.waker().to_owned());
            Poll::Pending
        }
    }
}

impl<T: Send + Unpin> Stream for Queue<T> {
    type Item = T;
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Self::poll_pop_front(self.get_mut(), cx)
    }
}
