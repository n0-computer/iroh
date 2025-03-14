//! TLS 1.3 certificates and handshakes handling.
//!
//! This module handles a verification of a client/server certificate chain
//! and signatures allegedly by the given certificates, or using raw public keys.
//!
//!
//! libp2p-tls certificate part is based on rust-libp2p/transports/tls/src/verifier.rs originally
//! licensed under MIT by Parity Technologies (UK) Ltd.

use std::sync::Arc;

use iroh_base::PublicKey;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms},
    pki_types::{pem::PemObject, CertificateDer as Certificate},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, PeerMisbehaved,
    SignatureScheme, SupportedProtocolVersion,
};
use webpki::{ring as webpki_algs, types::SubjectPublicKeyInfoDer};

use super::{certificate, Authentication};

/// The only TLS version we support is 1.3
pub static PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ED25519,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
    ],
};

/// Implementation of the `rustls` certificate verification traits.
///
/// Only TLS 1.3 is supported. TLS 1.2 should be disabled in the configuration of `rustls`.
#[derive(Debug)]
pub struct CertificateVerifier {
    /// The peer we intend to connect to.
    remote_peer_id: Option<PublicKey>,
    /// Which TLS authentication mode to operate in.
    auth: Authentication,
    trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
}

/// We require the following
/// Either X.509 server certificate chains:
///
/// - Exactly one certificate must be presented.
/// - The certificate must be self-signed.
/// - The certificate must have a valid libp2p extension that includes a signature of its public key.
///
/// or a raw public key.
impl CertificateVerifier {
    pub fn new(auth: Authentication) -> Self {
        Self::with_remote_peer_id(auth, None)
    }

    pub fn with_remote_peer_id(auth: Authentication, remote_peer_id: Option<PublicKey>) -> Self {
        let mut trusted_spki = Vec::new();
        if let Some(key) = remote_peer_id {
            let pem_key = key.serialize_public_pem();
            let remote_key = SubjectPublicKeyInfoDer::from_pem_slice(pem_key.as_bytes())
                .expect("cannot remote open pub key");
            trusted_spki.push(remote_key);
        }

        Self {
            remote_peer_id,
            auth,
            trusted_spki,
        }
    }
}

impl ServerCertVerifier for CertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.auth {
            Authentication::X509 => {
                let peer_id = verify_presented_certs(end_entity, intermediates)?;

                if let Some(ref remote_peer_id) = self.remote_peer_id {
                    // The public host key allows the peer to calculate the peer ID of the peer
                    // it is connecting to. Clients MUST verify that the peer ID derived from
                    // the certificate matches the peer ID they intended to connect to,
                    // and MUST abort the connection if there is a mismatch.
                    if remote_peer_id != &peer_id {
                        return Err(rustls::Error::PeerMisbehaved(
                            PeerMisbehaved::BadCertChainExtensions,
                        ));
                    }
                }
                Ok(ServerCertVerified::assertion())
            }
            Authentication::RawPublicKey => {
                if !intermediates.is_empty() {
                    return Err(rustls::Error::InvalidCertificate(
                        CertificateError::UnknownIssuer,
                    ));
                }
                if self.trusted_spki.is_empty() {
                    return Ok(ServerCertVerified::assertion());
                }
                let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());

                match self.trusted_spki.contains(&end_entity_as_spki) {
                    false => Err(rustls::Error::InvalidCertificate(
                        CertificateError::UnknownIssuer,
                    )),
                    true => Ok(ServerCertVerified::assertion()),
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match self.auth {
            Authentication::X509 => {
                verify_tls13_signature(cert, dss.scheme, message, dss.signature())
            }
            Authentication::RawPublicKey => verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                &SUPPORTED_SIG_ALGS,
            ),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED_SIG_ALGS.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        matches!(self.auth, Authentication::RawPublicKey)
    }
}

/// We requires either following of X.509 client certificate chains:
///
/// - Exactly one certificate must be presented. In particular, client
///   authentication is mandatory in libp2p.
/// - The certificate must be self-signed.
/// - The certificate must have a valid libp2p extension that includes a
///   signature of its public key.
///
/// or a valid raw public key configuration
impl ClientCertVerifier for CertificateVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        match self.auth {
            Authentication::X509 => {
                verify_presented_certs(end_entity, intermediates)?;
                Ok(ClientCertVerified::assertion())
            }
            Authentication::RawPublicKey => {
                if !intermediates.is_empty() {
                    return Err(rustls::Error::InvalidCertificate(
                        CertificateError::UnknownIssuer,
                    ));
                }
                if self.trusted_spki.is_empty() {
                    return Ok(ClientCertVerified::assertion());
                }
                let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
                match self.trusted_spki.contains(&end_entity_as_spki) {
                    false => Err(rustls::Error::InvalidCertificate(
                        CertificateError::UnknownIssuer,
                    )),
                    true => Ok(ClientCertVerified::assertion()),
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match self.auth {
            Authentication::X509 => {
                verify_tls13_signature(cert, dss.scheme, message, dss.signature())
            }
            Authentication::RawPublicKey => verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                &SUPPORTED_SIG_ALGS,
            ),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED_SIG_ALGS.supported_schemes()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[][..]
    }

    fn requires_raw_public_keys(&self) -> bool {
        matches!(self.auth, Authentication::RawPublicKey)
    }
}

/// When receiving the certificate chain, an endpoint
/// MUST check these conditions and abort the connection attempt if
/// (a) the presented certificate is not yet valid, OR
/// (b) if it is expired.
/// Endpoints MUST abort the connection attempt if more than one certificate is received,
/// or if the certificate’s self-signature is not valid.
fn verify_presented_certs(
    end_entity: &Certificate,
    intermediates: &[Certificate],
) -> Result<PublicKey, rustls::Error> {
    if !intermediates.is_empty() {
        return Err(rustls::Error::General(
            "libp2p-tls requires exactly one certificate".into(),
        ));
    }

    let cert = certificate::parse(end_entity)?;

    Ok(cert.peer_id())
}

fn verify_tls13_signature(
    cert: &Certificate,
    signature_scheme: SignatureScheme,
    message: &[u8],
    signature: &[u8],
) -> Result<HandshakeSignatureValid, rustls::Error> {
    certificate::parse(cert)?.verify_signature(signature_scheme, message, signature)?;

    Ok(HandshakeSignatureValid::assertion())
}

impl From<certificate::ParseError> for rustls::Error {
    fn from(certificate::ParseError(e): certificate::ParseError) -> Self {
        use webpki::Error::*;
        match e {
            BadDer => rustls::Error::InvalidCertificate(CertificateError::BadEncoding),
            e => {
                rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))
            }
        }
    }
}
impl From<certificate::VerificationError> for rustls::Error {
    fn from(certificate::VerificationError(e): certificate::VerificationError) -> Self {
        use webpki::Error::*;
        match e {
            InvalidSignatureForPublicKey => {
                rustls::Error::InvalidCertificate(CertificateError::BadSignature)
            }
            UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
                rustls::Error::InvalidCertificate(CertificateError::BadSignature)
            }
            e => {
                rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))
            }
        }
    }
}
