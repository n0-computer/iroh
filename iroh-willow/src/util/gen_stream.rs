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
pub struct GenStream<Y, E, Fut, O = ()>
where
    Fut: Future<Output = Result<O, E>>,
{
    #[debug("Gen")]
    gen: Gen<Y, (), Fut>,
    is_complete: bool,
    final_output: Option<O>,
}

impl<Y, E, Fut, O> GenStream<Y, E, Fut, O>
where
    Fut: Future<Output = Result<O, E>>,
{
    pub fn new(producer: impl FnOnce(Co<Y, ()>) -> Fut) -> Self {
        Self::from_gen(Gen::new(producer))
    }

    pub fn from_gen(gen: Gen<Y, (), Fut>) -> Self {
        Self {
            gen,
            is_complete: false,
            final_output: None,
        }
    }

    pub fn final_output(self) -> Option<O> {
        self.final_output
    }
}

impl<Y, E, Fut, O> futures_lite::Stream for GenStream<Y, E, Fut, O>
where
    Fut: Future<Output = Result<O, E>>,
    O: Unpin,
{
    type Item = Result<Y, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_complete {
            return Poll::Ready(None);
        }
        let (item, final_output) = {
            let mut fut = self.gen.async_resume();
            let out = std::task::ready!(Pin::new(&mut fut).poll(cx));
            match out {
                GeneratorState::Yielded(output) => (Some(Ok(output)), Option::None),
                GeneratorState::Complete(Ok(final_output)) => (None, Some(final_output)),
                GeneratorState::Complete(Err(err)) => (Some(Err(err)), None),
            }
        };
        if matches!(item, None | Some(Err(_))) {
            self.is_complete = true;
        }
        if let Some(final_output) = final_output {
            self.final_output = Some(final_output);
        };
        Poll::Ready(item)
    }
}
