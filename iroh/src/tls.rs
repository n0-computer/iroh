//! TLS configuration for iroh.
//!
//! Currently there is one mechanisms available
//! - Raw Public Keys, using the TLS extension described in [RFC 7250]
//!
//! [RFC 7250]: https://datatracker.ietf.org/doc/html/rfc7250

use std::sync::Arc;

use iroh_base::SecretKey;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use tracing::warn;

use self::resolver::AlwaysResolvesCert;

pub(crate) mod name;
mod resolver;
mod verifier;

/// Maximum amount of TLS tickets we will cache (by default) for 0-RTT connection
/// establishment.
///
/// 8 tickets per remote endpoint, 32 different endpoints would max out the required storage:
/// ~200 bytes per session + certificates (which are ~387 bytes)
/// So 8 * 32 * (200 + 387) = 150.272 bytes, assuming pointers to certificates
/// are never aliased pointers (they're Arc'ed).
/// I think 150KB is an acceptable default upper limit for such a cache.
pub(crate) const DEFAULT_MAX_TLS_TICKETS: usize = 8 * 32;

/// Configuration for TLS.
///
/// The main point of this struct is to keep state that should be kept the same
/// over multiple TLS sessions the same.
/// E.g. the `server_verifier` and `client_verifier` Arc pointers are checked to be
/// the same between different TLS session calls with 0-RTT data in rustls.
/// This makes sure that's the case.
#[derive(Debug)]
pub(crate) struct TlsConfig {
    pub(crate) secret_key: SecretKey,
    cert_resolver: Arc<AlwaysResolvesCert>,
    server_verifier: Arc<verifier::ServerCertificateVerifier>,
    client_verifier: Arc<verifier::ClientCertificateVerifier>,
    session_store: Arc<dyn rustls::client::ClientSessionStore>,
}

impl TlsConfig {
    pub(crate) fn new(secret_key: SecretKey, max_tls_tickets: usize) -> Self {
        let cert_resolver = Arc::new(
            AlwaysResolvesCert::new(&secret_key).expect("Client cert key DER is valid; qed"),
        );
        Self {
            secret_key,
            cert_resolver,
            server_verifier: Arc::new(verifier::ServerCertificateVerifier),
            client_verifier: Arc::new(verifier::ClientCertificateVerifier),
            session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(
                max_tls_tickets,
            )),
        }
    }

    /// Create a TLS client configuration.
    ///
    /// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
    /// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
    /// debugging purposes.
    pub(crate) fn make_client_config(
        &self,
        alpn_protocols: Vec<Vec<u8>>,
        keylog: bool,
    ) -> QuicClientConfig {
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("version supported by ring")
        .dangerous()
        .with_custom_certificate_verifier(self.server_verifier.clone())
        .with_client_cert_resolver(self.cert_resolver.clone());
        crypto.alpn_protocols = alpn_protocols;

        // TODO: enable/disable 0-RTT/storing tickets
        crypto.resumption = rustls::client::Resumption::store(self.session_store.clone());
        crypto.enable_early_data = true;

        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        crypto
            .try_into()
            .expect("expected to have a TLS1.3-compatible crypto provider set (hardcoded)")
    }

    /// Create a TLS server configuration.
    ///
    /// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
    /// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
    /// debugging purposes.
    pub(crate) fn make_server_config(
        &self,
        alpn_protocols: Vec<Vec<u8>>,
        keylog: bool,
    ) -> QuicServerConfig {
        let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("fixed config")
        .with_client_cert_verifier(self.client_verifier.clone())
        .with_cert_resolver(self.cert_resolver.clone());
        crypto.alpn_protocols = alpn_protocols;
        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        // must be u32::MAX or 0 (the default). Any other value panics with QUIC
        // This is specified in RFC 9001: https://www.rfc-editor.org/rfc/rfc9001#section-4.6.1
        crypto.max_early_data_size = u32::MAX;
        crypto
            .try_into()
            .expect("expected to have a TLS1.3-compatible crypto provider set (hardcoded)")
    }
}
