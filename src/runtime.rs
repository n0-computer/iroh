use futures::Future;
use std::sync::Arc;

/// A thread per core runtime.
///
/// This is just a convenient wrapper around multiple tokio current thread runtimes.
/// It has a similar API to the tokio runtime:
///
/// The runtime itself is not cloneable, and will shutdown when dropped.
/// You can obtain a handle to spawn tasks on the runtime, which is cheaply cloneable.
///
/// The runtime has a shutdown method that will wait for some time all tasks to finish.
pub mod tpc {
    use futures::{future::LocalBoxFuture, Future, FutureExt};
    use std::{fmt, time::Duration};

    /// A wrapper to manage multiple tokio runtimes in a thread per core fashion.
    pub struct Runtime {
        name: String,
        /// The handle to spawn tasks on the runtime
        handle: Handle,
        /// The sender to shutdown the runtimes
        shutdown_sender: tokio::sync::broadcast::Sender<()>,
        /// The handles to the threads
        handles: Vec<std::thread::JoinHandle<()>>,
    }

    impl fmt::Debug for Runtime {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ThreadPerCoreRuntime")
                .field("name", &self.name)
                .field("threads", &self.handles.len())
                .finish_non_exhaustive()
        }
    }

    /// The handle to spawn tasks on the runtime
    #[derive(Clone)]
    pub struct Handle {
        sender: flume::Sender<Task>,
    }

    impl fmt::Debug for Handle {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ThreadPerCoreRuntimeHandle").finish()
        }
    }

    struct Task(Box<dyn FnOnce() -> LocalBoxFuture<'static, ()> + Send + 'static>);

    impl Runtime {
        pub fn new(name: &str, n: usize) -> Self {
            let name = name.to_string();
            let (task_sender, task_receiver) = flume::bounded::<Task>(1);
            let (shutdown_sender, _) = tokio::sync::broadcast::channel::<()>(1);
            let handles = (0..n)
                .map(|i| {
                    let mut shutdown_receiver = shutdown_sender.subscribe();
                    let task_receiver = task_receiver.clone();
                    // name for the non blocking thread that we spawn
                    let main_name = format!("{}-{}", name, i);
                    // name for the blocking thread that the runtime spawns
                    let blocking_name = format!("{}-{}-blocking", name, i);
                    // spawn the thread
                    std::thread::Builder::new()
                        .name(main_name.clone())
                        .spawn(move || {
                            let local = tokio::task::LocalSet::new();
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .max_blocking_threads(1)
                                .thread_name(blocking_name)
                                .build()
                                .expect("failed to build tokio runtime");
                            rt.block_on(local.run_until(async move {
                                loop {
                                    tokio::select! {
                                        Ok(Task(f)) = task_receiver.recv_async() => {
                                            tokio::task::spawn_local(f());
                                        }
                                        Ok(()) = shutdown_receiver.recv() => {
                                            break;
                                        }
                                    }
                                }
                            }));
                            tracing::trace!("runtime {} dropped", main_name);
                        })
                        .expect("failed to spawn OS thread")
                })
                .collect::<Vec<_>>();
            Runtime {
                handle: Handle {
                    sender: task_sender,
                },
                name,
                shutdown_sender,
                handles,
            }
        }

        pub fn handle(&self) -> &Handle {
            &self.handle
        }

        /// Allow the given duration for a graceful shutdown, then abandon
        /// the threads and return.
        pub fn shutdown_timeout(mut self, duration: Duration) {
            tracing::trace!("shutting down runtime with timeout");
            // send the shutdown signal
            self.shutdown_sender.send(()).ok();
            // wait for all threads to finish
            let start = std::time::Instant::now();
            while start.elapsed() < duration {
                if self.handles.iter().all(|h| h.is_finished()) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            self.handles.clear();
        }

        /// Shutdown the runtime entirely in the background
        pub fn shutdown_background(self) {
            self.shutdown_timeout(Duration::from_secs(0));
        }
    }

    /// Signal to the runtime that it should shutdown, and wait indefinitely
    /// for it to do so.
    impl Drop for Runtime {
        fn drop(&mut self) {
            tracing::trace!("dropping runtime");
            self.shutdown_sender.send(()).ok();
            tracing::trace!("waiting for runtimes to terminate");
            for handle in self.handles.drain(..) {
                handle.join().ok();
            }
        }
    }

    impl Handle {
        pub async fn spawn<F, Fut>(&self, f: F)
        where
            F: FnOnce() -> Fut + Send + 'static,
            Fut: Future + 'static,
        {
            let f = || f().map(|_| ()).boxed_local();
            self.sender.send_async(Task(Box::new(f))).await.unwrap();
        }

        pub fn spawn_sync<F, Fut>(&self, f: F)
        where
            F: FnOnce() -> Fut + Send + 'static,
            Fut: Future + 'static,
            Fut::Output: 'static,
        {
            let f = || f().map(|_| ()).boxed_local();
            self.sender.send(Task(Box::new(f))).unwrap();
        }

        pub async fn run<F, Fut>(&self, f: F) -> Fut::Output
        where
            F: FnOnce() -> Fut + Send + 'static,
            Fut: Future + 'static,
            Fut::Output: Send + 'static,
        {
            let (tx, rx) = futures::channel::oneshot::channel();
            let f = || {
                f().map(|x| {
                    tx.send(x).ok();
                })
                .boxed_local()
            };
            self.sender.send_async(Task(Box::new(f))).await.unwrap();
            rx.await.unwrap()
        }

        pub fn run_sync<F, Fut>(&self, f: F) -> Fut::Output
        where
            F: FnOnce() -> Fut + Send + 'static,
            Fut: Future + 'static,
            Fut::Output: Send + 'static,
        {
            let (tx, rx) = std::sync::mpsc::channel();
            let f = move || {
                f().map(move |x| {
                    // on completion, send result back to caller
                    tx.send(x).ok();
                })
                .boxed_local()
            };
            // wait for completion (blocking)
            self.sender.send(Task(Box::new(f))).unwrap();
            rx.recv().unwrap()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            collections::BTreeSet,
            sync::{Arc, Mutex},
        };
        use tokio::task::LocalSet;
        use tracing_subscriber::{prelude::*, EnvFilter};

        fn thread_name() -> String {
            std::thread::current().name().unwrap().to_string()
        }

        #[test]
        fn tpc_runtime_smoke() {
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                .with(EnvFilter::from_default_env())
                .try_init()
                .ok();
            let rt = Runtime::new("test", num_cpus::get());
            let handle = rt.handle().clone();
            let values = Arc::new(Mutex::new(BTreeSet::new()));
            let values2 = values.clone();
            rt.handle().run_sync(|| async move {
                let values1 = values.clone();
                let values2 = values.clone();
                let values3 = values.clone();
                let values4 = values.clone();
                let values5 = values.clone();
                let values6 = values.clone();
                tracing::info!("Hello from main! {}", thread_name());
                // will use the same thread as the caller
                let h1 = tokio::task::spawn(async move {
                    tracing::info!("hello from spawn! {}", thread_name());
                    values1.lock().unwrap().insert("spawn");
                });
                // will use the same thread as the caller
                let h2 = tokio::task::spawn_local(async move {
                    tracing::info!("hello from spawn_local! {}", thread_name());
                    values2.lock().unwrap().insert("spawn_local");
                });
                // will use a thread from the blocking pool, but same number as the caller
                let h3 = tokio::task::spawn_blocking(move || {
                    tracing::info!("hello from spawn_blocking! {}", thread_name());
                    values3.lock().unwrap().insert("spawn_blocking");
                });
                // will choose a thread at random, might be different
                handle
                    .spawn(move || async move {
                        tracing::info!("hello from spawn_async! {}", thread_name());
                        values4.lock().unwrap().insert("spawn_async");
                    })
                    .await;
                // will choose a thread at random, might be different, awaits result
                handle
                    .run(move || async move {
                        tracing::info!("hello from run_async! {}", thread_name());
                        values5.lock().unwrap().insert("run_async");
                    })
                    .await;
                handle
                    .run(|| async move {
                        let ls = LocalSet::new();
                        ls.run_until(async move {
                            tracing::info!("hello from nested LocalSet! {}", thread_name());
                            values6.lock().unwrap().insert("nested_local_set");
                        })
                        .await;
                    })
                    .await;
                tracing::info!("awaiting spawn result");
                h1.await.unwrap();
                tracing::info!("awaiting spawn_local result");
                h2.await.unwrap();
                tracing::info!("awaiting spawn_blocking result");
                h3.await.unwrap();
                tracing::info!("done awaiting all the things");
            });
            drop(rt);
            let set = values2.lock().unwrap().clone();
            // check that all the things ran
            assert!(set.contains("spawn"));
            assert!(set.contains("spawn_local"));
            assert!(set.contains("spawn_blocking"));
            assert!(set.contains("spawn_async"));
            assert!(set.contains("run_async"));
            assert!(set.contains("nested_local_set"));
        }
    }
}

/// The iroh runtime, consisting of a generic tokio runtime and a number of
/// thread per core executors.
#[derive(Debug)]
pub struct Runtime {
    /// the runtime for misc tasks, like the acceptor
    rt: Option<tokio::runtime::Runtime>,
    /// the runtime for the thread per core executor
    tpc: tpc::Runtime,
    /// handle for cheap cloning
    handle: Handle,
}

impl Runtime {
    /// Create a new iroh runtime consisting of a tokio runtime and a thread per
    /// core runtime.
    pub fn new(rt: tokio::runtime::Handle, tpc: tpc::Runtime) -> Self {
        let handle = Handle {
            inner: Arc::new(HandleInner {
                rt,
                tpc: tpc.handle().clone(),
            }),
        };
        Self {
            rt: None,
            tpc,
            handle,
        }
    }

    /// Get a handle to the runtime
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Gracefully shut down the runtime for some time, then leave threads
    /// hanging and drop.
    pub fn shutdown_timeout(self, timeout: std::time::Duration) {
        // this actually might twice as long as the given timeout in the worst case,
        // because we have to wait for both the tokio runtime and the thread per core
        self.tpc.shutdown_timeout(timeout);
        // if we own the tokio runtime, shut it down too
        if let Some(rt) = self.rt {
            rt.shutdown_timeout(timeout);
        }
    }
}

#[derive(Debug)]
struct HandleInner {
    tpc: tpc::Handle,
    rt: tokio::runtime::Handle,
}

#[derive(Debug, Clone)]
pub struct Handle {
    inner: Arc<HandleInner>,
}

impl Handle {
    /// spawn a task on the main tokio runtime
    pub fn spawn<F>(&self, f: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.rt.spawn(f)
    }

    /// spawn a task on one of the thread per core executors
    pub async fn spawn_tpc<F, Fut, T>(&self, f: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
    {
        self.inner.tpc.spawn(f).await
    }
}
