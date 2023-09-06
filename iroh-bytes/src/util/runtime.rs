//! The runtime module provides the iroh runtime, consisting of a general purpose
//! tokio runtime and a set of single threaded runtimes.
use std::sync::Arc;

/// A handle to the iroh runtime
#[derive(Debug, Clone)]
pub struct Handle {
    inner: Arc<HandleInner>,
}

impl Handle {
    /// Create a new iroh runtime consisting of a tokio runtime and a thread per
    /// core runtime.
    pub fn new(rt: tokio::runtime::Handle, tpc: tokio_util::task::LocalPoolHandle) -> Self {
        Self {
            inner: Arc::new(HandleInner { rt, tpc }),
        }
    }

    /// Create a new iroh runtime using the current tokio runtime as the main
    /// runtime, and the given number of thread per core executors.
    pub fn from_current(
        size: usize,
    ) -> std::result::Result<Self, tokio::runtime::TryCurrentError> {
        Ok(Self::new(
            tokio::runtime::Handle::try_current()?,
            tokio_util::task::LocalPoolHandle::new(size),
        ))
    }

    /// Get a handle to the main tokio runtime
    pub fn main(&self) -> &tokio::runtime::Handle {
        &self.inner.rt
    }

    /// Get a handle to the thread pool for single threaded executors
    pub fn local_pool(&self) -> &tokio_util::task::LocalPoolHandle {
        &self.inner.tpc
    }
}

#[derive(Debug)]
struct HandleInner {
    rt: tokio::runtime::Handle,
    tpc: tokio_util::task::LocalPoolHandle,
}
