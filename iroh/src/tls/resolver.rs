use std::sync::Arc;

use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};
use iroh_base::SecretKey;
use n0_error::stack_error;
use webpki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};

#[derive(Debug)]
pub(super) struct AlwaysResolvesCert {
    key: Arc<rustls::sign::CertifiedKey>,
}

/// Error for generating TLS configs.
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[non_exhaustive]
pub(super) enum CreateConfigError {
    /// Rustls configuration error
    #[error("rustls error")]
    Rustls { source: rustls::Error },
}

impl AlwaysResolvesCert {
    pub(super) fn new(secret_key: &SecretKey) -> Result<Self, CreateConfigError> {
        // Directly use the key
        let client_private_key = secret_key
            .as_signing_key()
            .to_pkcs8_pem(LineEnding::default())
            .expect("key is valid");

        let client_private_key = PrivatePkcs8KeyDer::from_pem_slice(client_private_key.as_bytes())
            .expect("cannot open private key file");
        let provider = rustls::crypto::CryptoProvider::get_default()
            .expect("no default crypto provider installed");
        let client_private_key = provider
            .key_provider
            .load_private_key(client_private_key.into())
            .map_err(|e| rustls::Error::General(format!("failed to load private key: {e}")))?;

        // Send the public key as SPKI (SubjectPublicKeyInfo) DER encoding,
        // which is what the verifier expects when using raw public keys (RFC 7250).
        let client_public_key_spki = secret_key
            .public()
            .as_verifying_key()
            .to_public_key_der()
            .expect("valid key");
        let client_public_key_as_cert = CertificateDer::from(client_public_key_spki.into_vec());

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
