use std::sync::Arc;

use iroh_base::SecretKey;
use webpki::types::{pem::PemObject, CertificateDer, PrivatePkcs8KeyDer};

use super::{certificate, CreateConfigError};
use crate::tls::Authentication;

#[derive(Debug)]
pub(crate) struct AlwaysResolvesCert {
    key: Arc<rustls::sign::CertifiedKey>,
    auth: Authentication,
}

impl AlwaysResolvesCert {
    pub(crate) fn new(
        auth: Authentication,
        secret_key: &SecretKey,
    ) -> Result<Self, CreateConfigError> {
        let key = match auth {
            Authentication::X509 => {
                let (cert, key) = certificate::generate(secret_key)?;
                let certified_key = rustls::sign::CertifiedKey::new(
                    vec![cert],
                    rustls::crypto::ring::sign::any_ecdsa_type(&key)?,
                );
                Arc::new(certified_key)
            }
            Authentication::RawPublicKey => {
                // Directly use the key
                let client_private_key = secret_key.serialize_secret_pem();
                let client_private_key =
                    PrivatePkcs8KeyDer::from_pem_slice(client_private_key.as_bytes())
                        .expect("cannot open private key file");
                let client_private_key =
                    rustls::crypto::ring::sign::any_eddsa_type(&client_private_key)?;

                let client_public_key = client_private_key
                    .public_key()
                    .ok_or(rustls::Error::InconsistentKeys(
                        rustls::InconsistentKeys::Unknown,
                    ))
                    .expect("cannot load public key");
                let client_public_key_as_cert = CertificateDer::from(client_public_key.to_vec());

                let certified_key = rustls::sign::CertifiedKey::new(
                    vec![client_public_key_as_cert],
                    client_private_key,
                );

                Arc::new(certified_key)
            }
        };
        Ok(Self { key, auth })
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
        matches!(self.auth, Authentication::RawPublicKey)
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
        matches!(self.auth, Authentication::RawPublicKey)
    }
}
