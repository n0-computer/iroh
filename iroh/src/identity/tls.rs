//! Raw-public-key authentication for the identity endpoint.

use super::{Error, LocalIdentity, PeerId, Registry};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::sync::Arc;

pub(super) fn server(
    identity: &LocalIdentity,
    registry: Arc<Registry>,
    alpns: Vec<Vec<u8>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    keylog: bool,
) -> Result<noq::crypto::rustls::QuicServerConfig, Error> {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(Verifier {
            registry,
            expected: None,
        }))
        .with_cert_resolver(Arc::new(Resolver::new(identity)));
    if keylog {
        tls.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    tls.alpn_protocols = alpns;
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(noq::crypto::rustls::QuicServerConfig::try_from(tls)?)
}

pub(super) fn client(
    identity: &LocalIdentity,
    registry: Arc<Registry>,
    expected: PeerId,
    alpn: &[u8],
    provider: Arc<rustls::crypto::CryptoProvider>,
    keylog: bool,
) -> Result<noq::ClientConfig, Error> {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier {
            registry,
            expected: Some(expected),
        }))
        .with_client_cert_resolver(Arc::new(Resolver::new(identity)));
    if keylog {
        tls.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    tls.alpn_protocols = vec![alpn.to_vec()];
    tls.enable_sni = false;
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    let crypto = noq::crypto::rustls::QuicClientConfig::try_from(tls)?;
    Ok(noq::ClientConfig::new(Arc::new(crypto)))
}

#[derive(Debug)]
struct Resolver(Arc<rustls::sign::CertifiedKey>);

impl Resolver {
    fn new(identity: &LocalIdentity) -> Self {
        Self(identity.certified_key())
    }

    fn choose(&self, schemes: &[SignatureScheme]) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0.key.choose_scheme(schemes).map(|_| self.0.clone())
    }
}

impl rustls::client::ResolvesClientCert for Resolver {
    fn resolve(
        &self,
        _: &[&[u8]],
        schemes: &[SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.choose(schemes)
    }
    fn has_certs(&self) -> bool {
        true
    }
    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

impl rustls::server::ResolvesServerCert for Resolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.choose(hello.signature_schemes())
    }
    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct Verifier {
    registry: Arc<Registry>,
    expected: Option<PeerId>,
}

fn tls_error(error: Error) -> rustls::Error {
    rustls::Error::General(error.to_string())
}

impl Verifier {
    fn check(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), rustls::Error> {
        if !intermediates.is_empty() {
            return Err(tls_error(Error::PublicIdentity));
        }
        let id = self.registry.identify(cert.as_ref()).map_err(tls_error)?;
        if self.expected.is_some_and(|expected| expected != id) {
            return Err(tls_error(Error::IdentityMismatch));
        }
        Ok(())
    }

    fn signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.registry
            .verify(cert.as_ref(), message, signature)
            .map_err(tls_error)?;
        Ok(HandshakeSignatureValid::assertion())
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(cert, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.registry.schemes()
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for Verifier {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(cert, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.registry.schemes()
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
