use std::time::Duration;

use futures::Future;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};

/// A timer that works similar to golangs `Timer`.
#[derive(Debug)]
pub struct Timer {
    s: mpsc::Sender<Duration>,
    t: JoinHandle<()>,
}

impl Timer {
    /// Will trigger the execution of `f` after time `d` once.
    pub fn after<F>(d: Duration, f: F) -> Self
    where
        F: Future<Output = ()> + Send + Sync + 'static,
    {
        let (s, mut r) = mpsc::channel(1);

        let t = tokio::task::spawn(async move {
            let sleep = time::sleep(d);
            tokio::pin!(sleep);

            loop {
                tokio::select! {
                    biased;

                    msg = r.recv() => match msg {
                        Some(new_duration) => {
                            // Reset when a new duration was received.
                            sleep.as_mut().reset(Instant::now() + new_duration);
                        }
                        None => {
                            // dropped, end this
                            break;
                        }
                    },
                    _ = &mut sleep => {
                        // expired
                        f.await;
                        break;
                    }
                }
            }
        });

        Timer { s, t }
    }

    /// Reset the timer to stop after `d` has passed.
    pub async fn reset(&self, d: Duration) {
        self.s.send(d).await.ok();
    }

    /// Abort the timer.
    pub fn abort(self) {
        self.t.abort();
    }

    /// Returns true if not yet expired.
    pub async fn stop(self) -> bool {
        self.t.abort();
        // If the task was not completed yet, the abort triggers an error.
        self.t.await.is_err()
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
        assert!(timer.stop().await);
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

        assert!(!timer.stop().await);
        assert!(val.load(Ordering::Relaxed));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_timer_reset() {
        let val = Arc::new(AtomicBool::new(false));

        assert!(!val.load(Ordering::Relaxed));

        let moved_val = val.clone();
        let timer = Timer::after(Duration::from_millis(50), async move {
            moved_val.store(true, Ordering::Relaxed);
        });

        assert!(!val.load(Ordering::Relaxed));
        time::sleep(Duration::from_millis(25)).await;

        // not yet expired
        assert!(!val.load(Ordering::Relaxed));
        // reset for another 100ms
        timer.reset(Duration::from_millis(100)).await;

        // would have expired if not reset
        time::sleep(Duration::from_millis(25)).await;
        assert!(!val.load(Ordering::Relaxed));

        // definitely expired now
        time::sleep(Duration::from_millis(125)).await;
        assert!(val.load(Ordering::Relaxed));
    }
}
