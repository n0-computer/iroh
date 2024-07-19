//! A local task pool with proper shutdown
use std::{future::Future, ops::Deref, pin::Pin, sync::Arc};
use tokio::{sync::Semaphore, task::LocalSet};
use tokio_util::sync::CancellationToken;

type SpawnFn = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()>>> + Send + 'static>;

enum Message {
    /// Create a new task and execute it locally
    Execute(SpawnFn),
    /// Shutdown the thread, with an optional semaphore to signal when the thread
    /// has finished shutting down
    Shutdown(Option<Arc<Semaphore>>),
}

/// A local task pool with proper shutdown
///
/// Unlike
/// [`LocalPoolHandle`](https://docs.rs/tokio-util/latest/tokio_util/task/struct.LocalPoolHandle.html),
/// this pool will join all its threads when dropped, ensuring that all Drop
/// implementations are run to completion.
///
/// On drop, this pool will immediately cancel all tasks that are currently
/// being executed, and will wait for all threads to finish executing their
/// loops before returning. This means that all drop implementations will be
/// able to run to completion.
///
/// On [`LocalPool::shutdown`], this pool will notify all threads to shut down, and then
/// wait for all threads to finish executing their loops before returning.
#[derive(Debug)]
pub struct LocalPool {
    threads: Vec<std::thread::JoinHandle<()>>,
    cancel_token: CancellationToken,
    handle: LocalPoolHandle,
}

impl Deref for LocalPool {
    type Target = LocalPoolHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

/// A handle to a [`LocalPool`]
#[derive(Debug, Clone)]
pub struct LocalPoolHandle {
    /// The sender half of the channel used to send tasks to the pool
    send: flume::Sender<Message>,
}

impl Drop for LocalPool {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        for handle in self.threads.drain(..) {
            if let Err(cause) = handle.join() {
                tracing::error!("Error joining thread: {:?}", cause);
            }
        }
    }
}

/// Local task pool configuration
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Number of threads in the pool
    pub threads: usize,
    /// Size of the task queue, shared between threads
    pub queue_size: usize,
    /// Prefix for thread names
    pub thread_name_prefix: &'static str,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            queue_size: 1024,
            thread_name_prefix: "local-pool-",
        }
    }
}

impl LocalPool {
    /// Create a new task pool with `n` threads and a queue of size `queue_size`
    pub fn new(config: Config) -> Self {
        let Config {
            threads,
            queue_size,
            thread_name_prefix,
        } = config;
        let cancel_token = CancellationToken::new();
        let (send, recv) = flume::bounded::<Message>(queue_size);
        let handles = (0..threads)
            .map(|i| {
                Self::spawn_one(
                    format!("{thread_name_prefix}-{i}"),
                    recv.clone(),
                    cancel_token.clone(),
                )
            })
            .collect::<std::io::Result<Vec<_>>>()
            .expect("invalid thread name");
        Self {
            threads: handles,
            handle: LocalPoolHandle { send },
            cancel_token,
        }
    }

    /// Get a cheaply cloneable handle to the pool
    pub fn handle(&self) -> &LocalPoolHandle {
        &self.handle
    }

    /// Spawn a new task in the pool.
    fn spawn_one(
        task_name: String,
        recv: flume::Receiver<Message>,
        cancel_token: CancellationToken,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        std::thread::Builder::new().name(task_name).spawn(move || {
            let ls = LocalSet::new();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let sem_opt = ls.block_on(&rt, async {
                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            break None;
                        }
                        msg = recv.recv_async() => {
                            match msg {
                                Ok(Message::Execute(f)) => {
                                    let fut = (f)();
                                    ls.spawn_local(fut);
                                }
                                Ok(Message::Shutdown(sem_opt)) => break sem_opt,
                                Err(flume::RecvError::Disconnected) => break None,
                            }
                        }
                    }
                }
            });
            if let Some(sem) = sem_opt {
                sem.add_permits(1);
            }
        })
    }

    /// Cleanly shut down the pool
    ///
    /// Notifies all the pool threads to shut down and waits for them to finish.
    ///
    /// If you just want to drop the pool without giving the threads a chance to
    /// process their remaining tasks, just use drop.
    pub async fn shutdown(self) {
        let semaphore = Arc::new(Semaphore::new(0));
        let threads = self
            .threads
            .len()
            .try_into()
            .expect("invalid number of threads");
        for _ in 0..threads {
            self.send
                .send_async(Message::Shutdown(Some(semaphore.clone())))
                .await
                .expect("receiver dropped");
        }
        let _ = semaphore
            .acquire_many(threads)
            .await
            .expect("semaphore closed");
    }
}

impl LocalPoolHandle {
    /// Spawn a new task in the pool.
    ///
    /// Returns an error if the pool is shutting down.
    /// Will yield if the pool is busy.
    pub async fn spawn_local(&self, gen: SpawnFn) -> anyhow::Result<()> {
        let msg = Message::Execute(gen);
        self.send
            .send_async(msg)
            .await
            .map_err(|_e| anyhow::anyhow!("receiver dropped"))?;
        Ok(())
    }

    /// Spawn a new task in the pool.
    pub async fn spawn_pinned_detached<F, Fut>(&self, gen: F) -> anyhow::Result<()>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        self.spawn_local(Box::new(move || Box::pin(gen()))).await
    }

    /// Try to spawn a new task in the pool.
    ///
    /// Returns an error if the pool is shutting down.
    pub fn try_spawn_local(
        &self,
        gen: SpawnFn,
    ) -> std::result::Result<anyhow::Result<()>, SpawnFn> {
        let msg = Message::Execute(gen);
        match self.send.try_send(msg) {
            Ok(()) => Ok(Ok(())),
            Err(flume::TrySendError::Full(msg)) => {
                let Message::Execute(gen) = msg else {
                    unreachable!()
                };
                Err(gen)
            }
            Err(flume::TrySendError::Disconnected(_)) => {
                Ok(Err(anyhow::anyhow!("receiver dropped")))
            }
        }
    }

    /// Spawn a new task and return a tokio join handle.
    ///
    /// This comes with quite a bit of overhead, so only use this variant if you
    /// need to await the result of the task.
    ///
    /// The additional overhead is:
    /// - a tokio task
    /// - a tokio::sync::oneshot channel
    ///
    /// The overhead is necessary for this method to be synchronous and for it
    /// to return a tokio::task::JoinHandle.
    pub fn spawn_pinned<T, F, Fut>(&self, gen: F) -> tokio::task::JoinHandle<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let send = self.send.clone();
        tokio::spawn(async move {
            let (send_res, recv_res) = tokio::sync::oneshot::channel();
            let item: SpawnFn = Box::new(move || {
                let fut = (gen)();
                let res: Pin<Box<dyn Future<Output = ()>>> = Box::pin(async move {
                    let res = fut.await;
                    send_res.send(res).ok();
                });
                res
            });
            send.send_async(Message::Execute(item)).await.unwrap();
            recv_res.await.unwrap()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, sync::atomic::AtomicU64, time::Duration};

    use super::*;

    /// A struct that simulates a long running drop operation
    #[derive(Debug)]
    struct TestDrop(Arc<AtomicU64>);

    impl Drop for TestDrop {
        fn drop(&mut self) {
            // delay to make sure the drop is executed completely
            std::thread::sleep(Duration::from_millis(100));
            // increment the drop counter
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl TestDrop {
        fn new(counter: Arc<AtomicU64>) -> Self {
            Self(counter)
        }
    }

    /// Create a non-send test future that captures a TestDrop instance
    async fn non_send(x: TestDrop) {
        // just to make sure the future is not Send
        let t = Rc::new(RefCell::new(0));
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(t);
        // drop x at the end. we will never get here when the future is
        // no longer polled, but drop should still be called
        drop(x);
    }

    #[tokio::test]
    async fn test_drop() {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = LocalPool::new(Config::default());
        let counter = Arc::new(AtomicU64::new(0));
        let n = 4;
        for _ in 0..n {
            let td = TestDrop::new(counter.clone());
            pool.spawn_local(Box::new(move || Box::pin(non_send(td))))
                .await
                .unwrap();
        }
        drop(pool);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), n);
    }

    #[tokio::test]
    async fn test_shutdown() {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = LocalPool::new(Config::default());
        let counter = Arc::new(AtomicU64::new(0));
        let n = 4;
        for _ in 0..n {
            let td = TestDrop::new(counter.clone());
            pool.spawn_local(Box::new(move || Box::pin(non_send(td))))
                .await
                .unwrap();
        }
        pool.shutdown().await;
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), n);
    }
}
