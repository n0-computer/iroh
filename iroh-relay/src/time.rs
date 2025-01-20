//! Sleep and timeout utilities that work natively (via tokio) and in the browser.

#[cfg(not(wasm_browser))]
pub use tokio::time::{
    error::Elapsed, sleep, sleep_until, timeout, Duration, Instant, Sleep, Timeout,
};

#[cfg(wasm_browser)]
pub use wasm::{error::Elapsed, sleep, sleep_until, timeout, Duration, Instant, Sleep, Timeout};

#[cfg(wasm_browser)]
mod wasm {
    use futures_util::task::AtomicWaker;
    use send_wrapper::SendWrapper;
    use std::{
        future::{Future, IntoFuture},
        pin::Pin,
        sync::{
            atomic::{AtomicBool, Ordering::Relaxed},
            Arc,
        },
        task::{Context, Poll},
    };
    use wasm_bindgen::{closure::Closure, prelude::wasm_bindgen, JsCast, JsValue};

    pub use web_time::{Duration, Instant};

    /// Future that will wake up once its deadline is reached.
    #[derive(Debug)]
    pub struct Sleep {
        deadline: Instant,
        triggered: Flag,
        timeout_id: SendWrapper<JsValue>,
    }

    /// Sleeps for given duration
    pub fn sleep(duration: Duration) -> Sleep {
        let now = Instant::now();
        let deadline = now + duration;
        sleep_impl(duration, deadline)
    }

    /// Sleeps until given deadline
    pub fn sleep_until(deadline: Instant) -> Sleep {
        let now = Instant::now();
        let duration = deadline.duration_since(now);
        sleep_impl(duration, deadline)
    }

    fn sleep_impl(duration: Duration, deadline: Instant) -> Sleep {
        let triggered = Flag::new();

        let closure = Closure::once({
            let triggered = triggered.clone();
            move || triggered.signal()
        });

        let timeout_id = SendWrapper::new(
            set_timeout(
                closure.into_js_value().unchecked_into(),
                duration.as_millis() as i32,
            )
            .expect("missing setTimeout function on globalThis"),
        );

        Sleep {
            deadline,
            triggered,
            timeout_id,
        }
    }

    impl Future for Sleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut self.triggered).poll_signaled(cx)
        }
    }

    impl Drop for Sleep {
        fn drop(&mut self) {
            // If not, then in the worst case we're leaking a timeout
            if self.timeout_id.valid() {
                clear_timeout(self.timeout_id.as_ref().clone()).ok();
            }
        }
    }

    impl Sleep {
        /// Returns the instant at which the sleep is scheduled to wake up
        pub fn deadline(&self) -> Instant {
            self.deadline
        }

        /// Returns whether the sleep has reached its deadline
        /// (and the scheduler has handled the sleep's timer).
        pub fn is_elapsed(&self) -> bool {
            self.triggered.has_triggered()
        }

        /// Resets this sleep's deadline to given instant.
        ///
        /// Also works with sleeps that have already reached their deadline
        /// in the past.
        pub fn reset(mut self: Pin<&mut Self>, deadline: Instant) {
            let duration = deadline.duration_since(Instant::now());
            let triggered = Flag::new();

            let closure = Closure::once({
                let triggered = triggered.clone();
                move || {
                    tracing::trace!("timeout triggered");
                    triggered.signal()
                }
            });

            let timeout_id = SendWrapper::new(
                set_timeout(
                    closure.into_js_value().unchecked_into(),
                    duration.as_millis() as i32,
                )
                .expect("missing setTimeout function on globalThis"),
            );

            let mut this = self.as_mut();
            this.deadline = deadline;
            this.triggered = triggered;
            let old_timeout_id = std::mem::replace(&mut this.timeout_id, timeout_id);
            // If not valid, then in the worst case we're leaking a timeout task
            if old_timeout_id.valid() {
                clear_timeout(old_timeout_id.as_ref().clone()).ok();
            }
        }
    }

    /// Future that either resolves to [`error::Elapsed`] if the timeout
    /// is hit first. Otherwise, it resolves to `Ok` of the wrapped future.
    #[derive(Debug)]
    #[pin_project::pin_project]
    pub struct Timeout<T> {
        #[pin]
        future: T,
        #[pin]
        sleep: Sleep,
    }

    /// Error structs for time utilities (wasm mirror for `tokio::time::error`).
    pub mod error {
        /// Error when a timeout is elapsed.
        #[derive(Debug)]
        pub struct Elapsed;
    }

    /// Timeout of a function in wasm.
    pub fn timeout<F>(duration: Duration, future: F) -> Timeout<F::IntoFuture>
    where
        F: IntoFuture,
    {
        Timeout {
            future: future.into_future(),
            sleep: sleep(duration),
        }
    }

    impl<T: Future> Future for Timeout<T> {
        type Output = Result<T::Output, error::Elapsed>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.project();

            if let Poll::Ready(result) = this.future.poll(cx) {
                return Poll::Ready(Ok(result));
            }

            if let Poll::Ready(()) = this.sleep.poll(cx) {
                return Poll::Ready(Err(error::Elapsed));
            }

            Poll::Pending
        }
    }

    impl<T> Timeout<T> {
        /// Returns a reference of the wrapped future.
        pub fn get_ref(&self) -> &T {
            &self.future
        }

        /// Returns a mutable reference to the wrapped future.
        pub fn get_mut(&mut self) -> &mut T {
            &mut self.future
        }

        /// Returns the wrapped future and throws away and cancels the
        /// associated timeout.
        pub fn into_inner(self) -> T {
            self.future
        }
    }

    // Private impls

    #[derive(Clone, Debug)]
    struct Flag(Arc<Inner>);

    #[derive(Debug)]
    struct Inner {
        waker: AtomicWaker,
        set: AtomicBool,
    }

    impl Flag {
        fn new() -> Self {
            Self(Arc::new(Inner {
                waker: AtomicWaker::new(),
                set: AtomicBool::new(false),
            }))
        }

        fn has_triggered(&self) -> bool {
            self.0.set.load(Relaxed)
        }

        fn signal(&self) {
            self.0.set.store(true, Relaxed);
            self.0.waker.wake();
        }

        fn poll_signaled(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            // quick check to avoid registration if already done.
            if self.0.set.load(Relaxed) {
                return Poll::Ready(());
            }

            self.0.waker.register(cx.waker());

            // Need to check condition **after** `register` to avoid a race
            // condition that would result in lost notifications.
            if self.0.set.load(Relaxed) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    // Wasm-bindgen stuff

    #[wasm_bindgen]
    extern "C" {
        type GlobalScope;

        #[wasm_bindgen(catch, method, js_name = "setTimeout")]
        fn set_timeout_with_callback_and_timeout_and_arguments_0(
            this: &GlobalScope,
            handler: js_sys::Function,
            timeout: i32,
        ) -> Result<JsValue, JsValue>;

        #[wasm_bindgen(catch, method, js_name = "clearTimeout")]
        fn clear_timeout_with_handle(
            this: &GlobalScope,
            timeout_id: JsValue,
        ) -> Result<(), JsValue>;
    }

    fn set_timeout(handler: js_sys::Function, timeout: i32) -> Result<JsValue, JsValue> {
        tracing::trace!(?timeout, "setting timeout");
        let global_this = js_sys::global();
        let global_scope = global_this.unchecked_ref::<GlobalScope>();
        global_scope.set_timeout_with_callback_and_timeout_and_arguments_0(handler, timeout)
    }

    fn clear_timeout(timeout_id: JsValue) -> Result<(), JsValue> {
        let global_this = js_sys::global();
        let global_scope = global_this.unchecked_ref::<GlobalScope>();
        global_scope.clear_timeout_with_handle(timeout_id)
    }
}

#[cfg(test)]
mod tests {
    // TODO(matheus23): Write some tests for `sleep`, `sleep_until`, `timeout` and `Sleep::reset`
}
