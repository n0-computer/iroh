use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_lite::Stream;
use genawaiter::{
    rc::{Co, Gen},
    GeneratorState,
};

/// Wraps a [`Gen`] into a [`Stream`].
///
/// The stream yields the items yielded by the generator.
/// The generator's final output can be retrieved via [`Self::final_output`].
#[derive(derive_more::Debug)]
pub struct GenStream<Yield, Err, Fut, FinalOutput = ()>
where
    Fut: Future<Output = Result<FinalOutput, Err>>,
{
    #[debug("Gen")]
    gen: Gen<Yield, (), Fut>,
    is_complete: bool,
    final_output: Option<FinalOutput>,
}

impl<Yield, Err, Fut, FinalOutput> GenStream<Yield, Err, Fut, FinalOutput>
where
    Fut: Future<Output = Result<FinalOutput, Err>>,
{
    pub fn new(producer: impl FnOnce(Co<Yield, ()>) -> Fut) -> Self {
        Self::from_gen(Gen::new(producer))
    }

    pub fn from_gen(gen: Gen<Yield, (), Fut>) -> Self {
        Self {
            gen,
            is_complete: false,
            final_output: None,
        }
    }

    pub fn final_output(self) -> Option<FinalOutput> {
        self.final_output
    }
}

impl<Yield, Err, Fut, FinalOutput> Stream for GenStream<Yield, Err, Fut, FinalOutput>
where
    Fut: Future<Output = Result<FinalOutput, Err>>,
    FinalOutput: Unpin,
{
    type Item = Result<Yield, Err>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_complete {
            return Poll::Ready(None);
        }
        let (item, final_output) = {
            let mut fut = self.gen.async_resume();
            let out = std::task::ready!(Pin::new(&mut fut).poll(cx));
            match out {
                GeneratorState::Yielded(output) => (Some(Ok(output)), None),
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
