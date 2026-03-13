//! TLS 1.3 certificates and handshakes handling.
//!
//! This module handles a verification of a client/server certificate chain
//! and signatures allegedly by the given certificates, or using raw public keys.

use ed25519_dalek::pkcs8::EncodePublicKey;
use iroh_base::PublicKey;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme,
    SupportedProtocolVersion,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
    pki_types::CertificateDer as Certificate,
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use webpki_types::SubjectPublicKeyInfoDer;

/// The only TLS version we support is 1.3
pub(super) static PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

fn supported_sig_algs() -> WebPkiSupportedAlgorithms {
    rustls::crypto::CryptoProvider::get_default()
        .expect("no default crypto provider installed")
        .signature_verification_algorithms
}

/// Implementation of the `rustls` certificate verification traits
///
/// Only TLS 1.3 is supported. TLS 1.2 should be disabled in the configuration of `rustls`.
#[derive(Default, Debug)]
pub(super) struct ServerCertificateVerifier;

fn public_key_to_spki(remote_peer_id: &PublicKey) -> SubjectPublicKeyInfoDer<'static> {
    let der_key = remote_peer_id
        .as_verifying_key()
        .to_public_key_der()
        .expect("valid key");
    SubjectPublicKeyInfoDer::from(der_key.into_vec())
}

impl ServerCertVerifier for ServerCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let rustls::pki_types::ServerName::DnsName(dns_name) = server_name else {
            return Err(rustls::Error::UnsupportedNameType);
        };
        let Some(remote_peer_id) = super::name::decode(dns_name.as_ref()) else {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName,
            ));
        };

        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }

        let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());

        // This effectively checks that the `end_entity_as_spki` bytes have the expected
        // (constant) 12 byte prefix (consisting of the Ed25519 public key ASN.1 object
        // identifier, some ASN.1 DER encoding bytes signaling that this is a SPKI and
        // consists of the object identifier and a bit sequence, a zero byte indicating
        // that the bit sequence is padded with 0 additional bits) matches, as well as
        // the public key bytes match the `remote_peer_id` public key bytes.
        if public_key_to_spki(&remote_peer_id) != end_entity_as_spki {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }

        Ok(ServerCertVerified::assertion())
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
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &supported_sig_algs(),
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_sig_algs().supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Implementation of the `rustls` certificate verification traits.
///
/// Only TLS 1.3 is supported. TLS 1.2 should be disabled in the configuration of `rustls`.
#[derive(Default, Debug)]
pub(super) struct ClientCertificateVerifier;

/// We requires either following of X.509 client certificate chains:
///
/// - a valid raw public key configuration
impl ClientCertVerifier for ClientCertificateVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        _end_entity: &Certificate,
        intermediates: &[Certificate],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }

        Ok(ClientCertVerified::assertion())
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
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &supported_sig_algs(),
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_sig_algs().supported_schemes()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[][..]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
