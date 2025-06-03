use std::sync::Arc;

use n0_future::{
    task::{self, AbortOnDropHandle},
    time::{self, Duration},
};
use reloadable_state::Reloadable;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio_util::sync::CancellationToken;

/// The default certificate reload interval.
pub const DEFAULT_CERT_RELOAD_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);

/// A Certificate resolver that reloads the certificate every interval
#[derive(Debug)]
pub struct ReloadingResolver<Loader: Send + 'static> {
    /// The inner reloadable value.
    reloadable: Arc<Reloadable<CertifiedKey, Loader>>,
    /// The handle to the task that reloads the certificate.
    _handle: AbortOnDropHandle<()>,
    /// Cancel token to shutdown the resolver.
    cancel_token: CancellationToken,
}

impl<Loader> ReloadingResolver<Loader>
where
    Loader: Send + reloadable_state::core::Loader<Value = CertifiedKey> + 'static,
{
    /// Perform the initial load and construct the [`ReloadingResolver`].
    pub async fn init(loader: Loader, interval: Duration) -> Result<Self, Loader::Error> {
        let (reloadable, _) = Reloadable::init_load(loader).await?;
        let reloadable = Arc::new(reloadable);

        let cancel_token = CancellationToken::new();

        // Spawn a task to reload the certificate every interval.
        let _reloadable = reloadable.clone();
        let _cancel_token = cancel_token.clone();
        let _handle = task::spawn(async move {
            let mut interval = time::interval(interval);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let _ = _reloadable.reload().await;
                        tracing::info!("Reloaded the certificate");
                    },
                    _ = _cancel_token.cancelled() => {
                        tracing::trace!("shutting down");
                        break;
                    }
                }
            }
        });
        let _handle = AbortOnDropHandle::new(_handle);

        Ok(Self {
            reloadable,
            _handle,
            cancel_token,
        })
    }

    /// Shutdown the resolver.
    pub fn shutdown(self) {
        self.cancel_token.cancel();
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
