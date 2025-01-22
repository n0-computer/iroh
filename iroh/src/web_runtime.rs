use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use iroh_relay::time;

#[derive(Debug, Clone)]
pub struct WebRuntime;

#[derive(Debug)]
struct Timer(time::Sleep);

impl quinn::Runtime for WebRuntime {
    fn new_timer(&self, deadline: time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        Box::pin(Timer(time::sleep_until(deadline)))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        wasm_bindgen_futures::spawn_local(future);
    }
}

impl quinn::AsyncTimer for Timer {
    fn reset(mut self: Pin<&mut Self>, deadline: time::Instant) {
        Pin::new(&mut self.0).reset(deadline)
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.0).poll(cx)
    }
}
