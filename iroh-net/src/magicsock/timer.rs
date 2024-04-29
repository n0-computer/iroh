use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time;

/// A timer that works similar to golangs `Timer`.
#[derive(Debug)]
pub struct Timer {
    t: JoinHandle<()>,
}

impl Timer {
    /// Will trigger the execution of `f` after time `d` once.
    pub fn after<F>(d: Duration, f: F) -> Self
    where
        F: Future<Output = ()> + Send + Sync + 'static,
    {
        let t = tokio::task::spawn(async move {
            time::sleep(d).await;
            f.await
        });

        Timer { t }
    }

    /// Abort the timer.
    pub fn abort(self) {
        self.t.abort();
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.t).poll(cx).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use super::*;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_timer_success() {
        let val = Arc::new(AtomicBool::new(false));

        assert!(!val.load(Ordering::Relaxed));

        let moved_val = val.clone();
        let timer = Timer::after(Duration::from_millis(10), async move {
            moved_val.store(true, Ordering::Relaxed);
        });

        assert!(!val.load(Ordering::Relaxed));

        timer.await;
        assert!(val.load(Ordering::Relaxed));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_timer_abort() {
        let val = Arc::new(AtomicBool::new(false));

        assert!(!val.load(Ordering::Relaxed));

        let moved_val = val.clone();
        let timer = Timer::after(Duration::from_millis(10), async move {
            moved_val.store(true, Ordering::Relaxed);
        });

        assert!(!val.load(Ordering::Relaxed));
        timer.abort();
        assert!(!val.load(Ordering::Relaxed));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_timer_abort_late() {
        let val = Arc::new(AtomicBool::new(false));

        assert!(!val.load(Ordering::Relaxed));

        let moved_val = val.clone();
        let timer = Timer::after(Duration::from_millis(50), async move {
            moved_val.store(true, Ordering::Relaxed);
        });

        assert!(!val.load(Ordering::Relaxed));
        time::sleep(Duration::from_millis(75)).await;

        timer.abort();
        assert!(val.load(Ordering::Relaxed));
    }
}
