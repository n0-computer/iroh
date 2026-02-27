use std::sync::Arc;

use iroh_base::SecretKey;
use webpki_types::CertificateDer;

#[derive(Debug)]
pub(super) struct AlwaysResolvesCert {
    key: Arc<rustls::sign::CertifiedKey>,
}

impl AlwaysResolvesCert {
    pub(super) fn new(secret_key: &SecretKey) -> Self {
        let client_private_key = Arc::new(IrohSecretKey::from(secret_key.clone()));
        let client_public_key = client_private_key.spki_public_key();
        let client_public_key_as_cert = CertificateDer::from(client_public_key.to_vec());

        let certified_key =
            rustls::sign::CertifiedKey::new(vec![client_public_key_as_cert], client_private_key);

        let key = Arc::new(certified_key);

        Self { key }
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

#[derive(Debug, Clone, derive_more::From)]
struct IrohSecretKey {
    #[from]
    key: SecretKey,
}

impl IrohSecretKey {
    fn spki_public_key(&self) -> webpki_types::SubjectPublicKeyInfoDer<'static> {
        rustls::sign::public_key_to_spki(
            &webpki_types::alg_id::ED25519,
            self.key.public().as_bytes(),
        )
    }
}
impl rustls::sign::SigningKey for IrohSecretKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&rustls::SignatureScheme::ED25519) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }

    fn public_key(&self) -> Option<webpki_types::SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki_public_key())
    }
}

impl rustls::sign::Signer for IrohSecretKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.key.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ED25519
    }
}
