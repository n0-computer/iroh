//! The runtime module provides the iroh runtime, consisting of a general purpose
//! tokio runtime and a set of single threaded runtimes.
//!
//! Functions spawned on single threaded runtimes should not panic,
//! because panics will shut down the worker thread running the function, and
//! the runtime will not spawn new threads.
//!
//! It is best to run the entire program with panic = 'abort'.
use futures::{future::LocalBoxFuture, Future};
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
    use futures::future::LocalBoxFuture;
    #[cfg(test)]
    use futures::{Future, FutureExt};
    use std::{
        fmt,
        sync::{Arc, Mutex},
        time::Duration,
    };

    /// A wrapper to manage multiple tokio runtimes in a thread per core fashion.
    pub struct Runtime {
        name: String,
        /// The handle to spawn tasks on the runtime
        handle: Handle,
        /// The handles to the threads
        handles: Vec<std::thread::JoinHandle<()>>,
    }

    impl fmt::Debug for Runtime {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Runtime")
                .field("name", &self.name)
                .field("threads", &self.handles.len())
                .finish_non_exhaustive()
        }
    }

    /// The handle to spawn tasks on the runtime.
    ///
    /// This is cheaply cloneable, and can be sent to other threads.
    #[derive(Clone)]
    pub struct Handle {
        sender: Arc<Mutex<Option<flume::Sender<Task>>>>,
    }

    impl fmt::Debug for Handle {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Handle").finish()
        }
    }

    struct Task(Box<dyn FnOnce() -> LocalBoxFuture<'static, ()> + Send + 'static>);

    impl Runtime {
        pub fn new(name: &str, n: usize) -> Self {
            let name = name.to_string();
            let (task_sender, task_receiver) = flume::bounded::<Task>(1);
            let handles = (0..n)
                .map(|i| {
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
                                // this will run until recv_async returns an error, which happens
                                // when all senders are dropped. There is just one sender, which
                                // is dropped when the runtime is dropped.
                                while let Ok(Task(f)) = task_receiver.recv_async().await {
                                    tokio::task::spawn_local(f());
                                }
                            }));
                            tracing::trace!("runtime {} dropped", main_name);
                        })
                        .expect("failed to spawn OS thread")
                })
                .collect::<Vec<_>>();
            Runtime {
                handle: Handle {
                    sender: Arc::new(Mutex::new(Some(task_sender))),
                },
                name,
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
            // send the shutdown signal by dropping the sender
            self.handle.sender.lock().unwrap().take();
            // wait for all threads to finish
            let start = std::time::Instant::now();
            while start.elapsed() < duration {
                if self.handles.iter().all(|h| h.is_finished()) {
                    break;
                }
                std::hint::spin_loop();
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
            tracing::trace!("dropping sender");
            self.handle.sender.lock().unwrap().take();
            tracing::trace!("waiting for runtimes to terminate");
            for handle in self.handles.drain(..) {
                handle.join().ok();
            }
        }
    }

    impl Handle {
        fn sender(&self) -> flume::Sender<Task> {
            let inner = self.sender.lock().unwrap();
            let sender = inner.as_ref().expect("runtime dropped").clone();
            sender
        }

        /// Spawn a future on the runtime.
        ///
        /// Will not wait for the future to finish, but may yield while all runtimes are busy.
        pub async fn spawn<F>(&self, f: F)
        where
            F: FnOnce() -> LocalBoxFuture<'static, ()> + Send + 'static,
        {
            self.sender()
                .into_send_async(Task(Box::new(f)))
                .await
                .expect("runtime dropped");
        }

        /// Spawn a future on the runtime.
        ///
        /// Will not wait for the future to finish, but may block while all runtimes are busy.
        ///
        /// This would be needed to use this as a self contained runtime, but since we currently
        /// do not use it that way it is marked as cfg(test).
        #[cfg(test)]
        pub fn spawn_blocking<F>(&self, f: F)
        where
            F: FnOnce() -> LocalBoxFuture<'static, ()> + Send + 'static,
        {
            self.sender()
                .send(Task(Box::new(f)))
                .expect("runtime dropped");
        }

        /// Run a future on the runtime, and wait for it to finish.
        ///
        /// This would be needed to use this as a self contained runtime, but since we currently
        /// do not use it that way it is marked as cfg(test).
        #[cfg(test)]
        pub async fn run<F, Fut>(&self, f: F) -> Fut::Output
        where
            F: FnOnce() -> Fut + Send + 'static,
            Fut: Future + 'static,
            Fut::Output: Send + 'static,
        {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let f = || {
                f().map(|x| {
                    tx.send(x).ok();
                })
                .boxed_local()
            };
            self.sender()
                .into_send_async(Task(Box::new(f)))
                .await
                .expect("runtime dropped");
            rx.await.expect("runtime dropped")
        }

        /// Run a future on the runtime, and block until it finishes.
        ///
        /// This would be needed to use this as a self contained runtime, but since we currently
        /// do not use it that way it is marked as cfg(test).
        #[cfg(test)]
        pub fn run_blocking<F, Fut>(&self, f: F) -> Fut::Output
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
            self.sender()
                .send(Task(Box::new(f)))
                .expect("runtime dropped");
            rx.recv().expect("runtime dropped")
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
            rt.handle().run_blocking(|| async move {
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
                    .spawn(move || {
                        async move {
                            tracing::info!("hello from spawn_async! {}", thread_name());
                            values4.lock().unwrap().insert("spawn_async");
                        }
                        .boxed_local()
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

    /// Create a new iroh runtime using the current tokio runtime as the main
    /// runtime, and the given number of thread per core executors.
    pub fn from_currrent(
        name: &str,
        size: usize,
    ) -> std::result::Result<Self, tokio::runtime::TryCurrentError> {
        Ok(Self::new(
            tokio::runtime::Handle::try_current()?,
            crate::runtime::tpc::Runtime::new(name, size),
        ))
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
    pub async fn spawn_tpc<F>(&self, f: F)
    where
        F: FnOnce() -> LocalBoxFuture<'static, ()> + Send + 'static,
    {
        self.inner.tpc.spawn(f).await
    }
}
