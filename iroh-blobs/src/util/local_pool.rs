//! A local task pool with proper shutdown
use futures_buffered::FuturesUnordered;
use futures_lite::StreamExt;
use std::{
    future::Future,
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    task::Context,
};
use tokio::{
    sync::{Notify, Semaphore},
    task::{AbortHandle, LocalSet},
};

/// A lightweight cancellation token
#[derive(Debug, Clone)]
struct CancellationToken {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    is_cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
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

type BoxedFut<T = ()> = Pin<Box<dyn Future<Output = T>>>;
type SpawnFn<T = ()> = Box<dyn FnOnce() -> BoxedFut<T> + Send + 'static>;

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
/// On drop, this pool will immediately cancel all *tasks* that are currently
/// being executed, and will wait for all threads to finish executing their
/// loops before returning. This means that all drop implementations will be
/// able to run to completion before drop exits.
///
/// On [`LocalPool::shutdown`], this pool will notify all threads to shut down,
/// and then wait for all threads to finish executing their loops before
/// returning. This means that all currently executing tasks will be allowed to
/// run to completion.
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
#[derive(Clone, Debug)]
pub struct Config {
    /// Number of threads in the pool
    pub threads: usize,
    /// Prefix for thread names
    pub thread_name_prefix: &'static str,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            thread_name_prefix: "local-pool",
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
        } = config;
        let cancel_token = CancellationToken::new();
        let (send, recv) = flume::unbounded::<Message>();
        let handles = (0..threads)
            .map(|i| {
                Self::spawn_pool_thread(
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
    ///
    /// This is not strictly necessary since we implement deref for
    /// LocalPoolHandle, but makes getting a handle more explicit.
    pub fn handle(&self) -> &LocalPoolHandle {
        &self.handle
    }

    /// Spawn a new pool thread.
    fn spawn_pool_thread(
        task_name: String,
        recv: flume::Receiver<Message>,
        cancel_token: CancellationToken,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        std::thread::Builder::new().name(task_name).spawn(move || {
            let res = std::panic::catch_unwind(|| {
                let mut s = FuturesUnordered::new();
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let ls = LocalSet::new();
                let sem_opt = ls.block_on(&rt, async {
                    loop {
                        tokio::select! {
                            // poll the set of futures
                            _ = s.next() => {},
                            // if the cancel token is cancelled, break the loop immediately
                            _ = cancel_token.cancelled() => break None,
                            // if we receive a message, execute it
                            msg = recv.recv_async() => {
                                match msg {
                                    // just push into the FuturesUnordered
                                    Ok(Message::Execute(f)) => {
                                        let fut = (f)();
                                        // let fut = UnwindFuture::new(fut, "task");
                                        s.push(fut);
                                    },
                                    // break with optional semaphore
                                    Ok(Message::Shutdown(sem_opt)) => break sem_opt,
                                    // if the sender is dropped, break the loop immediately
                                    Err(flume::RecvError::Disconnected) => break None,
                                }
                            }
                        }
                    }
                });
                if let Some(sem) = sem_opt {
                    // somebody is asking for a clean shutdown, wait for all tasks to finish
                    ls.block_on(&rt, async {
                        loop {
                            tokio::select! {
                                res = s.next() => {
                                    if res.is_none() {
                                        break
                                    }
                                }
                                _ = cancel_token.cancelled() => break,
                            }
                        }
                    });
                    sem.add_permits(1);
                }
            });
            if let Err(payload) = res {
                // this thread is gone, so the entire thread pool is unusable.
                // cancel it all.
                cancel_token.cancel();
                tracing::error!("THREAD PANICKED YYY: {:?}", payload);
                std::panic::resume_unwind(payload);
            }
        })
    }

    /// Immediately stop polling all tasks and wait for all threads to finish.
    ///
    /// This is like Drop, but allows you to wait for the threads to finish and
    /// control from which thread the pool threads are joined.
    pub fn shutdown(mut self) {
        self.cancel_token.cancel();
        for handle in self.threads.drain(..) {
            if let Err(cause) = handle.join() {
                tracing::error!("Error joining thread: {:?}", cause);
            }
        }
    }

    /// Cleanly shut down the pool
    ///
    /// Notifies all the pool threads to shut down and waits for them to finish.
    ///
    /// If you just want to drop the pool without giving the threads a chance to
    /// process their remaining tasks, just use drop.
    ///
    /// If you want to wait for only a limited time for the tasks to finish,
    /// you can race this function with a timeout.
    pub async fn finish(self) {
        if self.cancel_token.is_cancelled() {
            return;
        }
        let semaphore = Arc::new(Semaphore::new(0));
        // convert to u32 for semaphore.
        let threads = self
            .threads
            .len()
            .try_into()
            .expect("invalid number of threads");
        // we assume that there are exactly as many threads as there are handles.
        // also, we assume that the threads are still running.
        for _ in 0..threads {
            self.send
                .send(Message::Shutdown(Some(semaphore.clone())))
                .expect("receiver dropped");
        }
        // wait for all threads to finish.
        // Each thread will add a permit to the semaphore.
        let wait_for_completion = async move {
            let _ = semaphore
                .acquire_many(threads)
                .await
                .expect("semaphore closed");
        };
        // race the shutdown with the cancellation, in case somebody cancels
        // during shutdown.
        futures_lite::future::race(wait_for_completion, self.cancel_token.cancelled()).await;
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
    /// This fn exists mostly for compatibility with tokio's `LocalPoolHandle`.
    /// It spawns an additional normal tokio task in order to be able to return
    /// a [`tokio::task::JoinHandle`]. Aborting the returned handle will
    /// cancel the task.
    pub fn spawn_pinned<T, F, Fut>(&self, gen: F) -> tokio::task::JoinHandle<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let inner = self.run(gen);
        let abort: Arc<OnceLock<AbortHandle>> = Arc::new(OnceLock::new());
        let abort2 = abort.clone();
        let res = tokio::spawn(async move {
            match inner.await {
                Ok(res) => res,
                Err(_) => {
                    // abort the outer task and wait forever (basically return pending)
                    abort.get().map(|a| a.abort());
                    futures_lite::future::pending().await
                }
            }
        });
        let _ = abort2.set(res.abort_handle());
        res
    }

    /// Run a task in the pool and await the result.
    ///
    /// When the returned future is dropped, the task will be immediately
    /// cancelled. Any drop implementation is guaranteed to run to completion in
    /// any case.
    pub fn run<T, F, Fut>(&self, gen: F) -> tokio::sync::oneshot::Receiver<T>
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
        self.run_detached(item);
        recv_res
    }

    /// Run a task in the pool.
    ///
    /// The task will be run detached. This can be useful if
    /// you are not interested in the result or in in cancellation or
    /// you provide your own result handling and cancellation mechanism.
    pub fn run_detached<F, Fut>(&self, gen: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let gen: SpawnFn = Box::new(move || Box::pin(gen()));
        self.run_detached_boxed(gen);
    }

    /// Run a task in the pool and await the result.
    ///
    /// This is like [`LocalPoolHandle::run_detached`], but assuming that the
    /// generator function is already boxed.
    pub fn run_detached_boxed(&self, gen: SpawnFn) {
        self.send
            .send(Message::Execute(gen))
            .expect("all receivers dropped");
    }
}

///
#[derive(Debug)]
#[pin_project::pin_project]
pub struct UnwindFuture<F> {
    #[pin]
    future: F,
    text: &'static str,
}

///
impl<F> UnwindFuture<F> {
    ///
    pub fn new(future: F, text: &'static str) -> Self {
        UnwindFuture { future, text }
    }
}

impl<F> Future for UnwindFuture<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();
        let text = *this.text;

        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| this.future.poll(cx))) {
            Ok(result) => result,
            Err(_panic) => {
                tracing::error!("Task XOXO {text} panicked");
                std::task::Poll::Pending
                // std::panic::resume_unwind(_panic);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, sync::atomic::AtomicU64, time::Duration};

    use super::*;

    #[allow(dead_code)]
    fn thread_name() -> String {
        std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string()
    }

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
    async fn non_send(x: TestDrop) {
        // just to make sure the future is not Send
        let t = Rc::new(RefCell::new(0));
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(t);
        // drop x at the end. we will never get here when the future is
        // no longer polled, but drop should still be called
        drop(x);
    }

    /// Use a TestDrop instance to test cancellation
    async fn non_send_cancel(x: TestDrop) {
        // just to make sure the future is not Send
        let t = Rc::new(RefCell::new(0));
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(t);
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
            pool.run_detached(move || non_send(td));
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
            pool.run_detached(move || non_send(td));
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
        let counter1 = Arc::new(AtomicU64::new(0));
        let td1 = TestDrop::new(counter1.clone());
        let handle = pool.spawn_pinned(Box::new(move || Box::pin(non_send_cancel(td1))));
        handle.abort();
        let counter2 = Arc::new(AtomicU64::new(0));
        let td2 = TestDrop::new(counter2.clone());
        let _handle = pool.spawn_pinned(Box::new(move || Box::pin(non_send_cancel(td2))));
        pool.finish().await;
        assert_eq!(counter1.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(counter2.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    #[ignore = "todo"]
    async fn test_panic() {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = LocalPool::new(Config {
            threads: 2,
            ..Config::default()
        });
        pool.run_detached(|| async {
            panic!("test panic");
        });
        pool.shutdown();
    }
}
