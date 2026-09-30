use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use iroh_base::EndpointId;
use portable_atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;
#[cfg(not(wasm_browser))]
use tokio_util::task::TaskTracker;

use crate::quic_time_source::{QuicInstant as Instant, QuicTimeSource};

#[derive(Debug)]
pub(crate) struct Runtime {
    id: EndpointId,
    time_source: Option<Arc<dyn QuicTimeSource>>,
    #[cfg(not(wasm_browser))]
    tasks: TaskTracker,
    #[cfg(not(wasm_browser))]
    cancel: CancellationToken,
    #[cfg(not(wasm_browser))]
    task_counter: AtomicU64,
}

impl Runtime {
    /// Create a new [`Runtime`] that manages shutting down tasks properly,
    /// whether gracefully or un-gracefully.
    pub(crate) fn new(id: EndpointId, time_source: Option<Arc<dyn QuicTimeSource>>) -> Self {
        Self {
            id,
            time_source,
            #[cfg(not(wasm_browser))]
            tasks: TaskTracker::new(),
            #[cfg(not(wasm_browser))]
            cancel: CancellationToken::new(),
            #[cfg(not(wasm_browser))]
            task_counter: AtomicU64::new(0),
        }
    }

    /// Shutdown the runtime gracefully.
    ///
    /// Closes the task tracker and waits for all spawned tasks to finish naturally.
    #[cfg(not(wasm_browser))]
    pub(crate) async fn shutdown(&self) {
        self.abort();
        // Waits for all tasks to stop (and thus drop all of their futures).
        // If the task tracker had already been closed and tasks have all been cleaned up,
        // this returns immediately.
        self.tasks.wait().await;
    }

    /// Shutdown the runtime ASAP, not waiting for any graceful closing of tasks.
    #[cfg(not(wasm_browser))]
    pub(crate) fn abort(&self) {
        // Signal all spawned tasks to stop immediately.
        self.cancel.cancel();
        // Signal that the runtime should be closed.
        self.tasks.close();
        // Does not wait for the tasks to return.
    }

    /// No-op on wasm. There is no task tracker to close or wait on.
    #[cfg(wasm_browser)]
    pub(crate) async fn shutdown(&self) {}

    /// No-op on wasm. There is no task tracker or cancellation to perform.
    #[cfg(wasm_browser)]
    pub(crate) fn abort(&self) {}
}

impl noq::Runtime for Runtime {
    #[cfg(not(wasm_browser))]
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn noq::AsyncTimer>> {
        if let Some(time_source) = &self.time_source {
            return Box::pin(TimeSourceTimer::new(time_source.clone(), i));
        }
        noq::TokioRuntime.new_timer(i)
    }

    #[cfg(wasm_browser)]
    fn new_timer(&self, deadline: n0_future::time::Instant) -> Pin<Box<dyn noq::AsyncTimer>> {
        if let Some(time_source) = &self.time_source {
            return Box::pin(TimeSourceTimer::new(time_source.clone(), deadline));
        }
        Box::pin(web::Timer(n0_future::time::sleep_until(deadline)))
    }

    #[cfg(not(wasm_browser))]
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        // Do not allow spawning more tasks if the runtime should be closed.
        if self.tasks.is_closed() {
            tracing::debug!(me = %self.id.fmt_short(), "runtime closed, dropping spawned task");
            return;
        }

        use tracing::{Instrument, trace_span};

        let task_id = self.task_counter.fetch_add(1, Ordering::Relaxed);
        let cancel = self.cancel.clone();
        let span = trace_span!("runtime", me = %self.id.fmt_short(), task_id);
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

    fn now(&self) -> Instant {
        if let Some(time_source) = &self.time_source {
            return time_source.now();
        }
        Instant::now()
    }

    // We're not actually using this function in iroh
    #[cfg(not(wasm_browser))]
    fn wrap_udp_socket(
        &self,
        t: std::net::UdpSocket,
    ) -> std::io::Result<Box<dyn noq::AsyncUdpSocket>> {
        noq::TokioRuntime.wrap_udp_socket(t)
    }
}

struct TimeSourceTimer {
    time_source: Arc<dyn QuicTimeSource>,
    sleep: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl TimeSourceTimer {
    fn new(time_source: Arc<dyn QuicTimeSource>, deadline: Instant) -> Self {
        let sleep = time_source.sleep_until(deadline);
        Self { time_source, sleep }
    }
}

impl fmt::Debug for TimeSourceTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeSourceTimer").finish_non_exhaustive()
    }
}

impl noq::AsyncTimer for TimeSourceTimer {
    fn reset(mut self: Pin<&mut Self>, deadline: Instant) {
        self.sleep = self.time_source.sleep_until(deadline);
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.sleep.as_mut().poll(cx)
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
    pub(crate) struct Timer(pub(crate) time::Sleep);

    impl noq::AsyncTimer for Timer {
        fn reset(mut self: Pin<&mut Self>, deadline: time::Instant) {
            Pin::new(&mut self.0).reset(deadline)
        }

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            Pin::new(&mut self.0).poll(cx)
        }
    }
}

#[cfg(all(test, not(wasm_browser)))]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
        time::{Duration, Instant},
    };

    use futures_util::task::AtomicWaker;
    use iroh_base::SecretKey;
    use noq::Runtime as _;

    use super::Runtime;
    use crate::quic_time_source::QuicTimeSource;

    #[derive(Debug)]
    struct TestTimeSource {
        now: Instant,
        sleeps: Mutex<Vec<(Instant, Arc<SleepState>)>>,
    }

    impl QuicTimeSource for TestTimeSource {
        fn now(&self) -> Instant {
            self.now
        }

        fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let state = Arc::new(SleepState::default());
            self.sleeps
                .lock()
                .expect("test sleep registry poisoned")
                .push((deadline, state.clone()));
            Box::pin(TestSleep { state })
        }
    }

    impl TestTimeSource {
        fn sleep(&self, index: usize) -> (Instant, Arc<SleepState>) {
            self.sleeps.lock().expect("test sleep registry poisoned")[index].clone()
        }
    }

    #[derive(Debug, Default)]
    struct SleepState {
        ready: AtomicBool,
        dropped: AtomicBool,
        waker: AtomicWaker,
    }

    impl SleepState {
        fn wake(&self) {
            self.ready.store(true, Ordering::Relaxed);
            self.waker.wake();
        }
    }

    #[derive(Debug)]
    struct TestSleep {
        state: Arc<SleepState>,
    }

    impl Future for TestSleep {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.state.ready.load(Ordering::Relaxed) {
                return Poll::Ready(());
            }
            self.state.waker.register(cx.waker());
            if self.state.ready.load(Ordering::Relaxed) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    impl Drop for TestSleep {
        fn drop(&mut self) {
            self.state.dropped.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn custom_time_source_drives_noq_clock_and_timers() {
        let now = Instant::now() + Duration::from_secs(10);
        let time_source = Arc::new(TestTimeSource {
            now,
            sleeps: Mutex::new(Vec::new()),
        });
        let runtime = Runtime::new(
            SecretKey::generate().public(),
            Some(time_source.clone() as Arc<dyn QuicTimeSource>),
        );

        assert_eq!(runtime.now(), now);
        let deadline = now + Duration::from_secs(1);
        let mut timer = runtime.new_timer(deadline);
        let (created_deadline, sleep) = time_source.sleep(0);
        assert_eq!(created_deadline, deadline);

        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(timer.as_mut().poll(&mut cx).is_pending());
        sleep.wake();
        assert!(timer.as_mut().poll(&mut cx).is_ready());
    }

    #[test]
    fn resetting_custom_timer_replaces_and_cancels_sleep() {
        let now = Instant::now();
        let time_source = Arc::new(TestTimeSource {
            now,
            sleeps: Mutex::new(Vec::new()),
        });
        let runtime = Runtime::new(
            SecretKey::generate().public(),
            Some(time_source.clone() as Arc<dyn QuicTimeSource>),
        );
        let mut timer = runtime.new_timer(now + Duration::from_secs(1));
        let (_, first) = time_source.sleep(0);

        let second_deadline = now + Duration::from_secs(2);
        timer.as_mut().reset(second_deadline);
        let (created_deadline, second) = time_source.sleep(1);
        assert_eq!(created_deadline, second_deadline);
        assert!(first.dropped.load(Ordering::Relaxed));

        first.wake();
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(timer.as_mut().poll(&mut cx).is_pending());
        second.wake();
        assert!(timer.as_mut().poll(&mut cx).is_ready());

        timer.as_mut().reset(now + Duration::from_secs(3));
        assert!(second.dropped.load(Ordering::Relaxed));
        assert!(timer.as_mut().poll(&mut cx).is_pending());
    }

    #[test]
    fn dropping_custom_timer_cancels_sleep() {
        let now = Instant::now();
        let time_source = Arc::new(TestTimeSource {
            now,
            sleeps: Mutex::new(Vec::new()),
        });
        let runtime = Runtime::new(
            SecretKey::generate().public(),
            Some(time_source.clone() as Arc<dyn QuicTimeSource>),
        );
        let timer = runtime.new_timer(now + Duration::from_secs(1));
        let (_, sleep) = time_source.sleep(0);
        drop(timer);
        assert!(sleep.dropped.load(Ordering::Relaxed));
    }

    #[test]
    fn default_runtime_uses_system_clock() {
        let runtime = Runtime::new(SecretKey::generate().public(), None);
        let before = Instant::now();
        let now = runtime.now();
        let after = Instant::now();
        assert!(now >= before && now <= after);
    }
}
