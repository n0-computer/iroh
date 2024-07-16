use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use genawaiter::{
    rc::{Co, Gen},
    GeneratorState,
};

#[derive(derive_more::Debug)]
pub struct GenStream<Y, E, Fut>
where
    Fut: Future<Output = Result<(), E>>,
{
    #[debug("Gen")]
    gen: Gen<Y, (), Fut>,
    is_complete: bool,
}

impl<Y, E, Fut> GenStream<Y, E, Fut>
where
    Fut: Future<Output = Result<(), E>>,
{
    pub fn new(producer: impl FnOnce(Co<Y, ()>) -> Fut) -> Self {
        Self::from_gen(Gen::new(producer))
    }

    pub fn from_gen(gen: Gen<Y, (), Fut>) -> Self {
        Self {
            gen,
            is_complete: false,
        }
    }
}

impl<Y, E, Fut> futures_lite::Stream for GenStream<Y, E, Fut>
where
    Fut: Future<Output = Result<(), E>>,
{
    type Item = Result<Y, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_complete {
            return Poll::Ready(None);
        }
        let item = {
            let mut fut = self.gen.async_resume();
            let out = std::task::ready!(Pin::new(&mut fut).poll(cx));
            match out {
                GeneratorState::Yielded(output) => Some(Ok(output)),
                GeneratorState::Complete(Ok(())) => None,
                GeneratorState::Complete(Err(err)) => Some(Err(err)),
            }
        };
        if matches!(item, None | Some(Err(_))) {
            self.is_complete = true;
        }
        Poll::Ready(item)
    }
}
