use std::pin::Pin;

use iroh_base::EndpointId;
#[cfg(not(wasm_browser))]
use tokio_util::task::TaskTracker;

#[derive(Debug)]
pub struct Runtime {
    ep: EndpointId,
    #[cfg(not(wasm_browser))]
    tasks: TaskTracker,
}

impl Runtime {
    pub fn new(ep: EndpointId) -> Self {
        Self {
            ep,
            #[cfg(not(wasm_browser))]
            tasks: TaskTracker::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub async fn shutdown(&self) {
        if self.tasks.close() {
            tracing::debug!("tasks len {}", self.tasks.len());
            self.tasks.wait().await
        }
    }
}

impl quinn::Runtime for Runtime {
    fn now(&self) -> std::time::Instant {
        // This will use tokio::time::Instant outside the browser,
        // allowing quinn to work correctly with tokio::time::pause().
        n0_future::time::Instant::now().into_std()
    }

    #[cfg(not(wasm_browser))]
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::TokioRuntime.new_timer(i)
    }

    #[cfg(wasm_browser)]
    fn new_timer(&self, deadline: n0_future::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        Box::pin(web::Timer(n0_future::time::sleep_until(deadline)))
    }

    #[cfg(not(wasm_browser))]
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        use tracing::{Instrument, Span};

        let ep = self.ep.fmt_short();
        self.tasks.spawn(async move {
            use rand::random_range;

            let id = random_range(0..100);
            tracing::warn!("{ep}: spawning task! {id}");
            future.instrument(Span::current()).await;
            tracing::warn!("{ep}: spawned task {id} is complete!");
        });
    }

    #[cfg(wasm_browser)]
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        wasm_bindgen_futures::spawn_local(future);
    }

    // We're not actually using this function in iroh
    #[cfg(not(wasm_browser))]
    fn wrap_udp_socket(
        &self,
        t: std::net::UdpSocket,
    ) -> std::io::Result<Box<dyn quinn::AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(t)
    }
}

#[cfg(wasm_browser)]
mod web {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    use n0_future::time;

    #[derive(Debug)]
    pub(crate) struct Timer(time::Sleep);

    impl quinn::AsyncTimer for Timer {
        fn reset(mut self: Pin<&mut Self>, deadline: time::Instant) {
            Pin::new(&mut self.0).reset(deadline)
        }

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            Pin::new(&mut self.0).poll(cx)
        }
    }
}
