use std::{
    borrow::Cow,
    io,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use anyhow::{bail, Context, Result};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use futures::{future::BoxFuture, FutureExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls_acme::{axum::AxumAcceptor, caches::DirCache, AcmeConfig};
use tokio_stream::StreamExt;
use tracing::{debug, error, info_span, Instrument};

/// The mode how SSL certificates should be created.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, strum::Display)]
#[serde(rename_all = "snake_case")]
pub enum CertMode {
    /// Certs are loaded from a the `cert_cache` path
    Manual,
    /// ACME with LetsEncrypt servers
    LetsEncrypt,
    /// Create self-signed certificates and store them in the `cert_cache` path
    SelfSigned,
}

impl CertMode {
    /// Build the [`TlsAcceptor`] for this mode.
    pub async fn build(
        &self,
        domains: Vec<String>,
        cert_cache: PathBuf,
        letsencrypt_contact: Option<String>,
        letsencrypt_prod: bool,
    ) -> Result<TlsAcceptor> {
        Ok(match self {
            CertMode::Manual => TlsAcceptor::manual(domains, cert_cache).await?,
            CertMode::SelfSigned => TlsAcceptor::self_signed(domains).await?,
            CertMode::LetsEncrypt => {
                let contact =
                    letsencrypt_contact.context("contact is required for letsencrypt cert mode")?;
                TlsAcceptor::letsencrypt(domains, &contact, letsencrypt_prod, cert_cache)?
            }
        })
    }
}

/// TLS Certificate Authority acceptor.
#[derive(Clone)]
pub enum TlsAcceptor {
    LetsEncrypt(AxumAcceptor),
    Manual(RustlsAcceptor),
}

impl<I: AsyncRead + AsyncWrite + Unpin + Send + 'static, S: Send + 'static> Accept<I, S>
    for TlsAcceptor
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = S;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        match self {
            Self::LetsEncrypt(a) => a.accept(stream, service).boxed(),
            Self::Manual(a) => a.accept(stream, service).boxed(),
        }
    }
}

impl TlsAcceptor {
    async fn self_signed(domains: Vec<String>) -> Result<Self> {
        let tls_cert = rcgen::generate_simple_self_signed(domains)?;
        let config = RustlsConfig::from_der(
            vec![tls_cert.serialize_der()?],
            tls_cert.serialize_private_key_der(),
        )
        .await?;
        let acceptor = RustlsAcceptor::new(config);
        Ok(Self::Manual(acceptor))
    }

    async fn manual(domains: Vec<String>, dir: PathBuf) -> Result<Self> {
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth();
        if domains.len() != 1 {
            bail!("Multiple domains in manual mode are not supported");
        }
        let keyname = escape_hostname(&domains[0]);
        let cert_path = dir.join(format!("{keyname}.crt"));
        let key_path = dir.join(format!("{keyname}.key"));

        let (certs, secret_key) = tokio::task::spawn_blocking(move || {
            let certs = load_certs(cert_path)?;
            let key = load_secret_key(key_path)?;
            anyhow::Ok((certs, key))
        })
        .await??;

        let config = config.with_single_cert(certs, secret_key)?;
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
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth();
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

fn load_certs(filename: impl AsRef<Path>) -> Result<Vec<rustls::Certificate>> {
    let certfile = std::fs::File::open(filename).context("cannot open certificate file")?;
    let mut reader = std::io::BufReader::new(certfile);

    let certs = rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();

    Ok(certs)
}

fn load_secret_key(filename: impl AsRef<Path>) -> Result<rustls::PrivateKey> {
    let keyfile = std::fs::File::open(filename.as_ref()).context("cannot open secret key file")?;
    let mut reader = std::io::BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).context("cannot parse secret key .pem file")? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    bail!(
        "no keys found in {} (encrypted keys not supported)",
        filename.as_ref().display()
    );
}

static UNSAFE_HOSTNAME_CHARACTERS: OnceLock<regex::Regex> = OnceLock::new();

fn escape_hostname(hostname: &str) -> Cow<'_, str> {
    let regex = UNSAFE_HOSTNAME_CHARACTERS
        .get_or_init(|| regex::Regex::new(r"[^a-zA-Z0-9-\.]").expect("valid regex"));
    regex.replace_all(hostname, "")
}
