use std::{
    borrow::Cow,
    io,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use n0_error::{Result, StackResultExt, StdResultExt, bail_any};
use n0_future::{FutureExt, future::Boxed as BoxFuture};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls_acme::{AcmeConfig, axum::AxumAcceptor, caches::DirCache};
use tokio_stream::StreamExt;
use tracing::{Instrument, debug, error, info_span};

/// Strategy used to obtain TLS certificates for the HTTPS server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, strum::Display)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertMode {
    /// Load pre-existing certificates from the `cert_cache` directory.
    Manual,
    /// Obtain certificates from Let's Encrypt via the ACME protocol.
    LetsEncrypt,
    /// Generate self-signed certificates and cache them in `cert_cache`.
    SelfSigned,
}

impl CertMode {
    /// Build the [`TlsAcceptor`] for this mode.
    pub(crate) async fn build(
        &self,
        domains: Vec<String>,
        cert_cache: PathBuf,
        letsencrypt_contact: Option<String>,
        letsencrypt_prod: bool,
    ) -> Result<TlsAcceptor> {
        Ok(match self {
            CertMode::Manual => TlsAcceptor::manual(domains, cert_cache).await?,
            CertMode::SelfSigned => TlsAcceptor::self_signed(domains)?,
            CertMode::LetsEncrypt => {
                let contact =
                    letsencrypt_contact.context("contact is required for letsencrypt cert mode")?;
                TlsAcceptor::letsencrypt(domains, &contact, letsencrypt_prod, cert_cache)?
            }
        })
    }
}

/// How long a client may take to complete the TLS handshake.
///
/// Generous, so that clients on lossy high-latency links still get through.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// TLS Certificate Authority acceptor.
#[derive(Clone)]
pub(crate) enum TlsAcceptor {
    LetsEncrypt(AxumAcceptor),
    Manual(RustlsAcceptor),
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> Accept<I, S>
    for TlsAcceptor
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = S;
    type Future = BoxFuture<io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accept = match self {
            Self::LetsEncrypt(a) => a.accept(stream, service).boxed(),
            Self::Manual(a) => a.accept(stream, service).boxed(),
        };
        // The ACME acceptor has no handshake timeout of its own.
        async move {
            tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, accept)
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS handshake timed out",
                    ))
                })
        }
        .boxed()
    }
}

impl TlsAcceptor {
    fn self_signed(domains: Vec<String>) -> Result<Self> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(domains).anyerr()?;
        let key = PrivateKeyDer::try_from(signing_key.serialize_der())?;

        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .anyerr()?
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key)
                .anyerr()?;

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = RustlsAcceptor::new(RustlsConfig::from_config(Arc::new(config)));
        Ok(Self::Manual(acceptor))
    }

    async fn manual(domains: Vec<String>, dir: PathBuf) -> Result<Self> {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .anyerr()?
        .with_no_client_auth();

        if domains.len() != 1 {
            bail_any!("Multiple domains in manual mode are not supported");
        }

        let keyname = escape_hostname(&domains[0]);
        let cert_path = dir.join(format!("{keyname}.crt"));
        let key_path = dir.join(format!("{keyname}.key"));

        let certs = load_certs(cert_path).await?;
        let secret_key = load_secret_key(key_path).await?;

        let config = config.with_single_cert(certs, secret_key).anyerr()?;
        let config = RustlsConfig::from_config(Arc::new(config));
        let acceptor = RustlsAcceptor::new(config);
        Ok(Self::Manual(acceptor))
    }

    fn letsencrypt(
        domains: Vec<String>,
        contact: &str,
        is_production: bool,
        dir: PathBuf,
    ) -> Result<Self> {
        let config = rustls::ServerConfig::builder().with_no_client_auth();
        let mut state = AcmeConfig::new(domains)
            .contact([format!("mailto:{contact}")])
            .cache_option(Some(DirCache::new(dir)))
            .directory_lets_encrypt(is_production)
            .state();

        let config = config.with_cert_resolver(state.resolver());
        let acceptor = state.acceptor();

        tokio::spawn(
            async move {
                loop {
                    match state.next().await.unwrap() {
                        Ok(ok) => debug!("acme event: {:?}", ok),
                        Err(err) => error!("error: {:?}", err),
                    }
                }
            }
            .instrument(info_span!("acme")),
        );
        let config = Arc::new(config);
        let acceptor = AxumAcceptor::new(acceptor, config);
        Ok(Self::LetsEncrypt(acceptor))
    }
}

async fn load_certs(filename: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>> {
    let filename = filename.as_ref();
    let certfile = tokio::fs::read(filename)
        .await
        .with_std_context(|_| format!("cannot open certificate file at {}", filename.display()))?;
    CertificateDer::pem_slice_iter(&certfile)
        .collect::<Result<Vec<_>, _>>()
        .with_std_context(|_| format!("cannot parse certificates from {}", filename.display()))
}

async fn load_secret_key(filename: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>> {
    let filename = filename.as_ref();
    let keyfile = tokio::fs::read(filename)
        .await
        .with_std_context(|_| format!("cannot open secret key file at {}", filename.display()))?;
    PrivateKeyDer::from_pem_slice(&keyfile)
        .with_std_context(|_| format!("cannot parse secret key from {}", filename.display()))
}

static UNSAFE_HOSTNAME_CHARACTERS: OnceLock<regex::Regex> = OnceLock::new();

fn escape_hostname(hostname: &str) -> Cow<'_, str> {
    let regex = UNSAFE_HOSTNAME_CHARACTERS
        .get_or_init(|| regex::Regex::new(r"[^a-zA-Z0-9-\.]").expect("valid regex"));
    regex.replace_all(hostname, "")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum_server::accept::Accept;
    use tokio::time::Instant;

    use super::{TLS_HANDSHAKE_TIMEOUT, TlsAcceptor};

    #[tokio::test(start_paused = true)]
    async fn test_handshake_timeout() {
        let TlsAcceptor::Manual(inner) =
            TlsAcceptor::self_signed(vec!["localhost".to_string()]).unwrap()
        else {
            unreachable!("self-signed mode uses the manual acceptor");
        };
        let acceptor = TlsAcceptor::Manual(inner.handshake_timeout(Duration::from_secs(3600)));
        let (_client, server_io) = tokio::io::duplex(1024);

        let start = Instant::now();
        let accept = acceptor.accept(server_io, ());
        let err = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(1), accept)
            .await
            .expect("handshake timeout did not fire")
            .expect_err("handshake cannot succeed without a client");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= TLS_HANDSHAKE_TIMEOUT);
    }
}
