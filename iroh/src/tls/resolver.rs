use std::sync::Arc;

use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey};
use iroh_base::SecretKey;
use nested_enum_utils::common_fields;
use snafu::Snafu;
use webpki_types::{pem::PemObject, CertificateDer, PrivatePkcs8KeyDer};

#[derive(Debug)]
pub(super) struct AlwaysResolvesCert {
    key: Arc<rustls::sign::CertifiedKey>,
}

/// Error for generating TLS configs.
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(super) enum CreateConfigError {
    /// Rustls configuration error
    #[snafu(display("rustls error"), context(false))]
    Rustls { source: rustls::Error },
}

impl AlwaysResolvesCert {
    pub(super) fn new(secret_key: &SecretKey) -> Result<Self, CreateConfigError> {
        // Directly use the key
        let client_private_key = secret_key
            .secret()
            .to_pkcs8_pem(LineEnding::default())
            .expect("key is valid");

        let client_private_key = PrivatePkcs8KeyDer::from_pem_slice(client_private_key.as_bytes())
            .expect("cannot open private key file");
        let client_private_key = rustls::crypto::ring::sign::any_eddsa_type(&client_private_key)?;

        let client_public_key = client_private_key
            .public_key()
            .ok_or(rustls::Error::InconsistentKeys(
                rustls::InconsistentKeys::Unknown,
            ))
            .expect("cannot load public key");
        let client_public_key_as_cert = CertificateDer::from(client_public_key.to_vec());

        let certified_key =
            rustls::sign::CertifiedKey::new(vec![client_public_key_as_cert], client_private_key);

        let key = Arc::new(certified_key);

        Ok(Self { key })
    }
}

impl rustls::client::ResolvesClientCert for AlwaysResolvesCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl rustls::server::ResolvesServerCert for AlwaysResolvesCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}
