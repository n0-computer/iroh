use std::{
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};

use iroh_base::EndpointId;
use tokio_util::sync::CancellationToken;
#[cfg(not(wasm_browser))]
use tokio_util::task::TaskTracker;

#[derive(Debug)]
pub struct Runtime {
    id: EndpointId,
    #[cfg(not(wasm_browser))]
    tasks: TaskTracker,
    cancel: CancellationToken,
    task_counter: AtomicU64,
}

impl Runtime {
    /// Create a new [`Runtime`] that manages shutting down tasks properly,
    /// whether gracefully or un-gracefully.
    pub fn new(id: EndpointId) -> Self {
        Self {
            id,
            #[cfg(not(wasm_browser))]
            tasks: TaskTracker::new(),
            cancel: CancellationToken::new(),
            task_counter: AtomicU64::new(0),
        }
    }

    /// Shutdown the runtime gracefully.
    ///
    /// Closes the task tracker and waits for all spawned tasks to finish naturally.
    #[cfg(not(wasm_browser))]
    pub async fn shutdown(&self) {
        if self.tasks.close() {
            self.tasks.wait().await
        }
    }

    /// Shutdown the runtime ASAP, not waiting for any graceful closing of tasks.
    #[cfg(not(wasm_browser))]
    // TODO: remove in next commit
    #[allow(dead_code)]
    pub fn abort(&self) {
        // Drop the running futures.
        self.cancel.cancel();
        // Signal that the runtime should be closed.
        self.tasks.close();
        // Does not wait for the tasks to return.
    }

    /// No-op on wasm. There is no task tracker to close or wait on.
    #[cfg(wasm_browser)]
    pub fn shutdown(&self) {}

    /// No-op on wasm. There is no task tracker or cancellation to perform.
    #[cfg(wasm_browser)]
    pub fn abort(&self) {}
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
        // Do not allow spawning more tasks if the runtime should be closed.
        if self.tasks.is_closed() {
            tracing::debug!(me = %self.id.fmt_short(), "runtime closed, dropping spawned task");
            return;
        }

        use tracing::{Instrument, debug_span};

        let task_id = self.task_counter.fetch_add(1, Ordering::Relaxed);
        let cancel = self.cancel.clone();
        let span = debug_span!("runtime", me = %self.id.fmt_short(), task_id);
        self.tasks.spawn(async move {
            // wrapping the future in a cancellation token is what allows
            // us to "abort" tasks in the event the runtime is meant to
            // close quickly and ungracefully
            cancel.run_until_cancelled(future.instrument(span)).await;
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
