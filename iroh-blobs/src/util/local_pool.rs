//! A local task pool with proper shutdown
use core::panic;
use std::{any::Any, future::Future, ops::Deref, pin::Pin, sync::Arc};
use tokio::{sync::Semaphore, task::LocalSet};
use tokio_util::sync::CancellationToken;

type SpawnFn = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()>>> + Send + 'static>;

enum Message {
    /// Create a new task and execute it locally
    Execute(SpawnFn),
    /// Shutdown the thread after finishing all tasks
    Finish,
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
    shutdown_sem: Arc<Semaphore>,
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
        let current_thread_id = std::thread::current().id();
        for handle in self.threads.drain(..) {
            // we have no control over from where Drop is called, especially
            // if the pool ends up in an Arc. So we need to check if we are
            // dropping from within a pool thread and skip it in that case.
            if handle.thread().id() == current_thread_id {
                tracing::error!("Dropping LocalPool from within a pool thread.");
                continue;
            }
            // Log any panics and resume them
            if let Err(panic) = handle.join() {
                let panic_info = get_panic_info(&panic);
                let thread_name = get_thread_name();
                tracing::error!("Error joining thread: {}\n{}", thread_name, panic_info);
                // std::panic::resume_unwind(panic);
            }
        }
    }
}

fn get_panic_info(panic: &Box<dyn Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "Panic info unavailable".to_string()
    }
}

fn get_thread_name() -> String {
    std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .to_string()
}

/// What to do when a panic occurs in a pool thread
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanicMode {
    /// Log the panic and continue
    ///
    /// The panic will be re-thrown when the pool is dropped.
    LogAndContinue,
    /// Log the panic and immediately shut down the pool.
    ///
    /// The panic will be re-thrown when the pool is dropped.
    Shutdown,
}

/// Local task pool configuration
#[derive(Clone, Debug)]
pub struct Config {
    /// Number of threads in the pool
    pub threads: usize,
    /// Prefix for thread names
    pub thread_name_prefix: &'static str,
    /// Ignore panics in pool threads
    pub panic_mode: PanicMode,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            thread_name_prefix: "local-pool",
            panic_mode: PanicMode::Shutdown,
        }
    }
}

impl Default for LocalPool {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl LocalPool {
    /// Create a new local pool with a single std thread.
    pub fn single() -> Self {
        Self::new(Config {
            threads: 1,
            ..Default::default()
        })
    }

    /// Create a new task pool with `n` threads and a queue of size `queue_size`
    pub fn new(config: Config) -> Self {
        let Config {
            threads,
            thread_name_prefix,
            panic_mode,
        } = config;
        let cancel_token = CancellationToken::new();
        let (send, recv) = flume::unbounded::<Message>();
        let shutdown_sem = Arc::new(Semaphore::new(0));
        let handles = (0..threads)
            .map(|i| {
                Self::spawn_pool_thread(
                    format!("{thread_name_prefix}-{i}"),
                    recv.clone(),
                    cancel_token.clone(),
                    shutdown_sem.clone(),
                    panic_mode,
                )
            })
            .collect::<std::io::Result<Vec<_>>>()
            .expect("invalid thread name");
        Self {
            threads: handles,
            handle: LocalPoolHandle { send },
            cancel_token,
            shutdown_sem,
        }
    }

    /// Get a cheaply cloneable handle to the pool
    pub fn handle(&self) -> &LocalPoolHandle {
        &self.handle
    }

    /// Spawn a new task in the pool.
    fn spawn_pool_thread(
        task_name: String,
        recv: flume::Receiver<Message>,
        cancel_token: CancellationToken,
        shutdown_sem: Arc<Semaphore>,
        _panic_mode: PanicMode,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        std::thread::Builder::new().name(task_name).spawn(move || {
            let ls = LocalSet::new();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            ls.block_on(&rt, async {
                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            break;
                        }
                        msg = recv.recv_async() => {
                            match msg {
                                Ok(Message::Execute(f)) => {
                                    let fut = (f)();
                                    ls.spawn_local(fut);
                                }
                                Ok(Message::Finish) => break,
                                Err(flume::RecvError::Disconnected) => break,
                            }
                        }
                    }
                }
            });
            shutdown_sem.add_permits(1);
        })
    }

    /// Gently shut down the pool
    ///
    /// Notifies all the pool threads to shut down and waits for them to finish.
    ///
    /// If you just want to drop the pool without giving the threads a chance to
    /// process their remaining tasks, just use [`Self::shutdown`].
    ///
    /// If you want to wait for only a limited time for the tasks to finish,
    /// you can race this function with a timeout.
    pub async fn finish(self) {
        // we assume that there are exactly as many threads as there are handles.
        // also, we assume that the threads are still running.
        for _ in 0..self.threads_u32() {
            println!("sending shutdown message");
            // send the shutdown message
            // sending will fail if all threads are already finished, but
            // in that case we don't need to do anything.
            //
            // Threads will add a permit in any case, so await_thread_completion
            // will then immediately return.
            self.send.send(Message::Finish).ok();
        }
        self.await_thread_completion().await;
    }

    fn threads_u32(&self) -> u32 {
        self.threads
            .len()
            .try_into()
            .expect("invalid number of threads")
    }

    async fn await_thread_completion(&self) {
        // wait for all threads to finish.
        // Each thread will add a permit to the semaphore.
        let wait_for_semaphore = async move {
            let _ = self
                .shutdown_sem
                .acquire_many(self.threads_u32())
                .await
                .expect("semaphore closed");
        };
        // race the semaphore wait with the cancel token in case somebody
        // cancels the pool while we are waiting.
        tokio::select! {
            _ = wait_for_semaphore => {}
            _ = self.cancel_token.cancelled() => {}
        }
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
        pool.finish().await;
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), n);
    }
}
