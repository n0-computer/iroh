//! A local task pool with proper shutdown
use futures_lite::FutureExt;
use std::{
    any::Any,
    future::Future,
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
};
use tokio::{
    sync::{Notify, Semaphore},
    task::{AbortHandle, JoinError, JoinSet, LocalSet},
};

type BoxedFut<T = ()> = Pin<Box<dyn Future<Output = T>>>;
type SpawnFn<T = ()> = Box<dyn FnOnce() -> BoxedFut<T> + Send + 'static>;

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
/// On drop, this pool will immediately cancel all *tasks* that are currently
/// being executed, and will wait for all threads to finish executing their
/// loops before returning. This means that all drop implementations will be
/// able to run to completion before drop exits.
///
/// On [`LocalPool::finish`], this pool will notify all threads to shut down,
/// and then wait for all threads to finish executing their loops before
/// returning. This means that all currently executing tasks will be allowed to
/// run to completion.
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

    /// Create a new local pool with the given config.
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
                    panic_mode,
                    shutdown_sem.clone(),
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
    ///
    /// This is not strictly necessary since we implement deref for
    /// LocalPoolHandle, but makes getting a handle more explicit.
    pub fn handle(&self) -> &LocalPoolHandle {
        &self.handle
    }

    /// Spawn a new pool thread.
    fn spawn_pool_thread(
        thread_name: String,
        recv: flume::Receiver<Message>,
        cancel_token: CancellationToken,
        panic_mode: PanicMode,
        shutdown_sem: Arc<Semaphore>,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let mut s = JoinSet::new();
                let mut last_panic = None;
                let mut handle_join = |res: Option<std::result::Result<(), JoinError>>| -> bool {
                    if let Some(Err(e)) = res {
                        if let Ok(panic) = e.try_into_panic() {
                            let panic_info = get_panic_info(&panic);
                            let thread_name = get_thread_name();
                            tracing::error!(
                                "Panic in local pool thread: {}\n{}",
                                thread_name,
                                panic_info
                            );
                            last_panic = Some(panic);
                        }
                    }
                    panic_mode == PanicMode::LogAndContinue || last_panic.is_none()
                };
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let ls = LocalSet::new();
                ls.enter();
                let shutdown_mode = ls.block_on(&rt, async {
                    loop {
                        tokio::select! {
                            // poll the set of futures
                            res = s.join_next(), if !s.is_empty() => {
                                if !handle_join(res) {
                                    break ShutdownMode::Stop;
                                }
                            },
                            // if the cancel token is cancelled, break the loop immediately
                            _ = cancel_token.cancelled() => break ShutdownMode::Stop,
                            // if we receive a message, execute it
                            msg = recv.recv_async() => {
                                match msg {
                                    // just push into the FuturesUnordered
                                    Ok(Message::Execute(f)) => {
                                        s.spawn_local((f)());
                                    }
                                    // break with optional semaphore
                                    Ok(Message::Finish) => break ShutdownMode::Finish,
                                    // if the sender is dropped, break the loop immediately
                                    Err(flume::RecvError::Disconnected) => break ShutdownMode::Stop,
                                }
                            }
                        }
                    }
                });
                // soft shutdown mode is just like normal running, except that
                // we don't add any more tasks and stop when there are no more
                // tasks to run.
                if shutdown_mode == ShutdownMode::Finish {
                    // somebody is asking for a clean shutdown, wait for all tasks to finish
                    ls.block_on(&rt, async {
                        loop {
                            tokio::select! {
                                res = s.join_next() => {
                                    if res.is_none() || !handle_join(res) {
                                        break;
                                    }
                                }
                                _ = cancel_token.cancelled() => break,
                            }
                        }
                    });
                }
                // Always add the permit. If nobody is waiting for it, it does
                // no harm.
                shutdown_sem.add_permits(1);
                if let Some(_panic) = last_panic {
                    // std::panic::resume_unwind(panic);
                }
            })
    }

    /// A future that resolves when the pool is cancelled
    pub async fn cancelled(&self) {
        self.cancel_token.cancelled().await
    }

    /// Immediately stop polling all tasks and wait for all threads to finish.
    ///
    /// This is like droo, but waits for thread completion asynchronously.
    ///
    /// If there was a panic on any of the threads, it will be re-thrown here.
    pub async fn shutdown(self) {
        self.cancel_token.cancel();
        self.await_thread_completion().await;
        // just make it explicit that this is where drop runs
        drop(self);
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

/// Errors for spawn failures
#[derive(thiserror::Error, Debug)]
pub enum SpawnError {
    /// Pool is shut down
    #[error("pool is shut down")]
    Shutdown,
}

type SpawnResult<T> = std::result::Result<T, SpawnError>;

/// Future returned by [`LocalPoolHandle::run`] and [`LocalPoolHandle::try_run`].
///
/// Dropping this future will immediately cancel the task. The task can fail if
/// the pool is shut down.
#[repr(transparent)]
#[derive(Debug)]
pub struct Run<T>(tokio::sync::oneshot::Receiver<T>);

impl<T> Run<T> {
    /// Abort the task
    ///
    /// Dropping the future will also abort the task.
    pub fn abort(&mut self) {
        self.0.close();
    }
}

impl<T> Future for Run<T> {
    type Output = std::result::Result<T, SpawnError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.0.poll(cx).map_err(|_| SpawnError::Shutdown)
    }
}

impl From<SpawnError> for std::io::Error {
    fn from(e: SpawnError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

impl LocalPoolHandle {
    /// Get the number of tasks in the queue
    ///
    /// This is *not* the number of tasks being executed, but the number of
    /// tasks waiting to be scheduled for execution. If this number is high,
    /// it indicates that the pool is very busy.
    ///
    /// You might want to use this to throttle or reject requests.
    pub fn waiting_tasks(&self) -> usize {
        self.send.len()
    }

    /// Spawn a new task and return a tokio join handle.
    ///
    /// This is like [`LocalPoolHandle::spawn_pinned`], but does not panic if
    /// the pool is shut down.
    pub fn try_spawn_pinned<T, F, Fut>(&self, gen: F) -> SpawnResult<tokio::task::JoinHandle<T>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let inner = self.try_run(gen)?;
        let abort: Arc<OnceLock<AbortHandle>> = Arc::new(OnceLock::new());
        let abort2 = abort.clone();
        let res = tokio::spawn(async move {
            match inner.await {
                Ok(res) => res,
                Err(_) => {
                    // abort the outer task and wait forever (basically return pending)
                    if let Some(abort) = abort.get() {
                        abort.abort();
                    }
                    futures_lite::future::pending().await
                }
            }
        });
        let _ = abort2.set(res.abort_handle());
        Ok(res)
    }

    /// Run a task in the pool and await the result.
    ///
    /// When the returned future is dropped, the task will be immediately
    /// cancelled. Any drop implementation is guaranteed to run to completion in
    /// any case.
    pub fn try_run<T, F, Fut>(&self, gen: F) -> SpawnResult<Run<T>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let (mut send_res, recv_res) = tokio::sync::oneshot::channel();
        let item = move || async move {
            let fut = (gen)();
            tokio::select! {
                // send the result to the receiver
                res = fut => { send_res.send(res).ok(); }
                // immediately stop the task if the receiver is dropped
                _ = send_res.closed() => {}
            }
        };
        self.try_spawn(item)?;
        Ok(Run(recv_res))
    }

    /// Run a task in the pool.
    ///
    /// The task will be run detached. This can be useful if
    /// you are not interested in the result or in in cancellation or
    /// you provide your own result handling and cancellation mechanism.
    pub fn try_spawn<F, Fut>(&self, gen: F) -> SpawnResult<()>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let gen: SpawnFn = Box::new(move || Box::pin(gen()));
        self.try_spawn_boxed(gen)
    }

    /// Run a task in the pool and await the result.
    ///
    /// This is like [`LocalPoolHandle::spawn`], but assuming that the
    /// generator function is already boxed.
    pub fn try_spawn_boxed(&self, gen: SpawnFn) -> SpawnResult<()> {
        self.send
            .send(Message::Execute(gen))
            .map_err(|_| SpawnError::Shutdown)
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

    // /// Spawn a new task and return a tokio join handle.
    // ///
    // /// This fn exists mostly for compatibility with tokio's `LocalPoolHandle`.
    // /// It spawns an additional normal tokio task in order to be able to return
    // /// a [`tokio::task::JoinHandle`]. Aborting the returned handle will
    // /// cancel the task.
    // pub fn spawn_pinned<T, F, Fut>(&self, gen: F) -> tokio::task::JoinHandle<T>
    // where
    //     F: FnOnce() -> Fut + Send + 'static,
    //     Fut: Future<Output = T> + 'static,
    //     T: Send + 'static,
    // {
    //     self.try_spawn_pinned(gen).expect("pool is shut down")
    // }

    /// Run a task in the pool and await the result.
    ///
    /// Like [`LocalPoolHandle::try_run`], but panics if the pool is shut down.
    pub fn run<T, F, Fut>(&self, gen: F) -> Run<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        self.try_run(gen).expect("pool is shut down")
    }

    /// Spawn a task in the pool.
    ///
    /// Like [`LocalPoolHandle::try_spawn`], but panics if the pool is shut down.
    pub fn spawn<F, Fut>(&self, gen: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        self.try_spawn(gen).expect("pool is shut down")
    }

    /// Spawn a boxed task in the pool.
    ///
    /// Like [`LocalPoolHandle::try_spawn_boxed`], but panics if the pool is shut down.
    pub fn spawn_boxed(&self, gen: SpawnFn) {
        self.try_spawn_boxed(gen).expect("pool is shut down")
    }
}

/// Thread shutdown mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownMode {
    /// Finish all tasks and then stop
    Finish,
    /// Stop immediately
    Stop,
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

/// A lightweight cancellation token
#[derive(Debug, Clone)]
struct CancellationToken {
    inner: Arc<CancellationTokenInner>,
}

#[derive(Debug)]
struct CancellationTokenInner {
    is_cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    fn new() -> Self {
        Self {
            inner: Arc::new(CancellationTokenInner {
                is_cancelled: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    fn cancel(&self) {
        if !self.inner.is_cancelled.swap(true, Ordering::SeqCst) {
            self.inner.notify.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }

        // Wait for notification if not cancelled
        self.inner.notify.notified().await;
    }

    fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::AtomicU64, time::Duration};

    use super::*;

    /// A struct that simulates a long running drop operation
    #[derive(Debug)]
    struct TestDrop(Option<Arc<AtomicU64>>);

    impl Drop for TestDrop {
        fn drop(&mut self) {
            // delay to make sure the drop is executed completely
            std::thread::sleep(Duration::from_millis(100));
            // increment the drop counter
            if let Some(counter) = self.0.take() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    impl TestDrop {
        fn new(counter: Arc<AtomicU64>) -> Self {
            Self(Some(counter))
        }

        fn forget(mut self) {
            self.0.take();
        }
    }

    /// Create a non-send test future that captures a TestDrop instance
    async fn delay_then_drop(x: TestDrop) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        // drop x at the end. we will never get here when the future is
        // no longer polled, but drop should still be called
        drop(x);
    }

    /// Use a TestDrop instance to test cancellation
    async fn delay_then_forget(x: TestDrop, delay: Duration) {
        tokio::time::sleep(delay).await;
        x.forget();
    }

    #[tokio::test]
    async fn test_drop() {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = LocalPool::new(Config::default());
        let counter = Arc::new(AtomicU64::new(0));
        let n = 4;
        for _ in 0..n {
            let td = TestDrop::new(counter.clone());
            pool.spawn(move || delay_then_drop(td));
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
            pool.spawn(move || delay_then_drop(td));
        }
        pool.finish().await;
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), n);
    }

    #[tokio::test]
    async fn test_cancel() {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = LocalPool::new(Config {
            threads: 2,
            ..Config::default()
        });
        let c1 = Arc::new(AtomicU64::new(0));
        let td1 = TestDrop::new(c1.clone());
        let handle = pool.run(move || {
            // this one will be aborted anyway, so use a long delay to make sure
            // that it does not accidentally run to completion
            delay_then_forget(td1, Duration::from_secs(10))
        });
        drop(handle);
        let c2 = Arc::new(AtomicU64::new(0));
        let td2 = TestDrop::new(c2.clone());
        let _handle = pool.run(move || {
            // this one will not be aborted, so use a short delay so the test
            // does not take too long
            delay_then_forget(td2, Duration::from_millis(100))
        });
        pool.finish().await;
        // c1 will be aborted, so drop will run before forget, so the counter will be increased
        assert_eq!(c1.load(std::sync::atomic::Ordering::SeqCst), 1);
        // c2 will not be aborted, so drop will run after forget, so the counter will not be increased
        assert_eq!(c2.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    #[should_panic]
    #[ignore = "todo"]
    async fn test_panic() {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = LocalPool::new(Config {
            threads: 2,
            ..Config::default()
        });
        pool.spawn(|| async {
            panic!("test panic");
        });
        // we can't use shutdown here, because we need to allow time for the
        // panic to happen.
        pool.finish().await;
    }
}
