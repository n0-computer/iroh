use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use reloadable_state::Reloadable;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio_util::task::AbortOnDropHandle;

/// A Certificate resolver that reloads the certificate every interval
#[derive(Debug)]
pub struct ReloadingResolver<Loader: Send + 'static> {
    /// The inner reloadable value.
    reloadable: Arc<Reloadable<CertifiedKey, Loader>>,
    /// The handle to the task that reloads the certificate.
    _handle: AbortOnDropHandle<()>,
    /// Shutdown signal sender
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl<Loader> ReloadingResolver<Loader>
where
    Loader: Send + reloadable_state::core::Loader<Value = CertifiedKey> + 'static,
{
    /// Perform the initial load and construct the [`ReloadingResolver`].
    pub async fn init(loader: Loader, interval: Duration) -> Result<Self> {
        let (reloadable, _) = Reloadable::init_load(loader)
            .await
            .map_err(|_| anyhow!("Failed to load the certificate"))?;
        let reloadable = Arc::new(reloadable);

        // create a channel to send the shutdown signal
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // Spawn a task to reload the certificate every interval.
        let _reloadable = reloadable.clone();
        let _handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            tokio::select! {
                _ = async {
                    loop {
                        interval.tick().await;
                        let _ = _reloadable.reload().await;
                        tracing::info!("Reloaded the certificate");
                    }
                } => {},
                _ = shutdown_rx => {
                    tracing::info!("Shutdown signal received");
                }
            }
        });
        let _handle = AbortOnDropHandle::new(_handle);

        Ok(Self {
            reloadable,
            _handle,
            _shutdown_tx: shutdown_tx,
        })
    }

    /// Shutdown the resolver.
    pub fn shutdown(self) {
        let _ = self._shutdown_tx.send(());
    }

    /// Reload the certificate.
    pub async fn reload(&self) {
        let _ = self.reloadable.reload().await;
    }
}

impl<Loader> ResolvesServerCert for ReloadingResolver<Loader>
where
    Loader: reloadable_state::core::Loader<Value = CertifiedKey>,
    Loader: Send,
    Loader: std::fmt::Debug,
{
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.reloadable.get())
    }
}

impl<Loader: Send> std::ops::Deref for ReloadingResolver<Loader> {
    type Target = Reloadable<CertifiedKey, Loader>;

    fn deref(&self) -> &Self::Target {
        &self.reloadable
    }
}
