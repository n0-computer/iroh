use std::{path::PathBuf, sync::Arc};

use n0_error::{AnyError, StdResultExt};
use n0_future::{
    task::{self, AbortOnDropHandle},
    time::{self, Duration},
};
use reloadable_state::Reloadable;
use rustls::{
    crypto::CryptoProvider,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_cert_reloadable_resolver::{CertifiedKeyLoader, key_provider::Dyn};
use tokio_util::sync::CancellationToken;

/// The default certificate reload interval.
pub const DEFAULT_CERT_RELOAD_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);

/// Builds a [`ResolvesServerCert`] that reloads its certificate and key from disk on an interval.
///
/// Loads the PEM-encoded certificate chain from `cert_path` and the PEM-encoded private key
/// from `key_path` using `crypto_provider`'s key provider, then spawns a background task that
/// re-reads both files every `interval`. The returned resolver hands the most recently loaded
/// `CertifiedKey` to rustls for each TLS handshake, so certificate rotation takes effect without
/// restarting the server. See [`DEFAULT_CERT_RELOAD_INTERVAL`] for a sensible default.
///
/// The reload task is tied to the returned `Arc` and is aborted when the last reference is
/// dropped. Reload failures on the interval are silently ignored; the previously loaded
/// certificate remains in use.
///
/// # Errors
///
/// Returns an error if the initial certificate or key load fails (for example, the files do not
/// exist, cannot be read, or cannot be parsed as PEM).
pub async fn reloading_resolver(
    crypto_provider: &CryptoProvider,
    cert_path: PathBuf,
    key_path: PathBuf,
    interval: std::time::Duration,
) -> Result<Arc<dyn ResolvesServerCert>, AnyError> {
    let key_reader =
        rustls_cert_file_reader::FileReader::new(key_path, rustls_cert_file_reader::Format::PEM);
    let certs_reader =
        rustls_cert_file_reader::FileReader::new(cert_path, rustls_cert_file_reader::Format::PEM);
    let loader = CertifiedKeyLoader {
        key_provider: Dyn(crypto_provider.key_provider),
        key_reader,
        certs_reader,
    };
    let resolver = ReloadingResolver::init(loader, interval)
        .await
        .std_context("cert loading")?;
    Ok(Arc::new(resolver))
}

/// A Certificate resolver that reloads the certificate every interval
#[derive(Debug)]
struct ReloadingResolver<Loader: Send + 'static> {
    /// The inner reloadable value.
    reloadable: Arc<Reloadable<CertifiedKey, Loader>>,
    /// The handle to the task that reloads the certificate.
    _handle: AbortOnDropHandle<()>,
}

impl<Loader> ReloadingResolver<Loader>
where
    Loader: Send + reloadable_state::core::Loader<Value = CertifiedKey> + 'static,
{
    /// Perform the initial load and construct the [`ReloadingResolver`].
    async fn init(loader: Loader, interval: Duration) -> Result<Self, Loader::Error> {
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
        })
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
