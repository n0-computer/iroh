//! X.509 certificate handling.
//!
//! This module handles generation, signing, and verification of certificates.
//!
//! Based on rust-libp2p/transports/tls/src/certificate.rs originally licensed under MIT by Parity
//! Technologies (UK) Ltd.

use der::{asn1::OctetStringRef, Decode, Encode, Sequence};
use x509_parser::prelude::*;

use crate::key::{PublicKey, SecretKey, Signature};

/// The libp2p Public Key Extension is a X.509 extension
/// with the Object Identier 1.3.6.1.4.1.53594.1.1,
/// allocated by IANA to the libp2p project at Protocol Labs.
const P2P_EXT_OID: [u64; 9] = [1, 3, 6, 1, 4, 1, 53594, 1, 1];

/// The peer signs the concatenation of the string `libp2p-tls-handshake:`
/// and the public key that it used to generate the certificate carrying
/// the libp2p Public Key Extension, using its private host key.
/// This signature provides cryptographic proof that the peer was
/// in possession of the private host key at the time the certificate was signed.
const P2P_SIGNING_PREFIX: [u8; 21] = *b"libp2p-tls-handshake:";

// Certificates MUST use the NamedCurve encoding for elliptic curve parameters.
// Similarly, hash functions with an output length less than 256 bits MUST NOT be used.
static P2P_SIGNATURE_ALGORITHM: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

/// The public host key and the signature are ANS.1-encoded
/// into the SignedKey data structure, which is carried  in the libp2p Public Key Extension.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SignedKey<'a> {
    public_key: OctetStringRef<'a>,
    signature: OctetStringRef<'a>,
}

/// Generates a self-signed TLS certificate that includes a libp2p-specific
/// certificate extension containing the public key of the given secret key.
pub fn generate(
    identity_secret_key: &SecretKey,
) -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    GenError,
> {
    // SecretKey used to sign the certificate.
    // SHOULD NOT be related to the host's key.
    // Endpoints MAY generate a new key and certificate
    // for every connection attempt, or they MAY reuse the same key
    // and certificate for multiple connections.
    let certificate_keypair = rcgen::KeyPair::generate(P2P_SIGNATURE_ALGORITHM)?;
    let rustls_key =
        rustls::pki_types::PrivateKeyDer::try_from(certificate_keypair.serialize_der()).unwrap();
    let certificate = {
        let mut params = rcgen::CertificateParams::new(vec![]);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.custom_extensions.push(make_libp2p_extension(
            identity_secret_key,
            &certificate_keypair,
        )?);
        params.alg = P2P_SIGNATURE_ALGORITHM;
        params.key_pair = Some(certificate_keypair);
        rcgen::Certificate::from_params(params)?
    };

    let rustls_certificate = rustls::pki_types::CertificateDer::from(certificate.serialize_der()?);

    Ok((rustls_certificate, rustls_key))
}

/// Attempts to parse the provided bytes as a [`P2pCertificate`].
///
/// For this to succeed, the certificate must contain the specified extension and the signature must
/// match the embedded public key.
pub fn parse<'a, 'b>(
    certificate: &'b rustls::pki_types::CertificateDer<'a>,
) -> Result<P2pCertificate<'b>, ParseError> {
    let certificate = parse_unverified(certificate.as_ref())?;

    certificate.verify()?;

    Ok(certificate)
}

/// An X.509 certificate with a libp2p-specific extension
/// is used to secure libp2p connections.
#[derive(Debug)]
pub struct P2pCertificate<'a> {
    certificate: X509Certificate<'a>,
    /// This is a specific libp2p Public Key Extension with two values:
    /// * the public host key
    /// * a signature performed using the private host key
    extension: P2pExtension,
}

/// The contents of the specific libp2p extension, containing the public host key
/// and a signature performed using the private host key.
#[derive(Debug)]
pub struct P2pExtension {
    public_key: crate::key::PublicKey,
    /// This signature provides cryptographic proof that the peer was
    /// in possession of the private host key at the time the certificate was signed.
    signature: crate::key::Signature,
}

/// An error that occurs during certificate generation.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct GenError(#[from] rcgen::RcgenError);

/// An error that occurs during certificate parsing.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ParseError(#[from] pub(crate) webpki::Error);

/// An error that occurs during signature verification.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct VerificationError(#[from] pub(crate) webpki::Error);

/// Internal function that only parses but does not verify the certificate.
///
/// Useful for testing but unsuitable for production.
fn parse_unverified(der_input: &[u8]) -> Result<P2pCertificate, webpki::Error> {
    let x509 = X509Certificate::from_der(der_input)
        .map(|(_rest_input, x509)| x509)
        .map_err(|_| webpki::Error::BadDer)?;

    let p2p_ext_oid = der_parser::oid::Oid::from(&P2P_EXT_OID)
        .expect("This is a valid OID of p2p extension; qed");

    let mut libp2p_extension = None;

    for ext in x509.extensions() {
        let oid = &ext.oid;
        if oid == &p2p_ext_oid && libp2p_extension.is_some() {
            // The extension was already parsed
            return Err(webpki::Error::BadDer);
        }

        if oid == &p2p_ext_oid {
            let signed_key =
                SignedKey::from_der(ext.value).map_err(|_| webpki::Error::ExtensionValueInvalid)?;
            let public_key_raw = signed_key.public_key.as_bytes();
            let public_key =
                PublicKey::try_from(public_key_raw).map_err(|_| webpki::Error::UnknownIssuer)?;

            let signature = Signature::from_slice(signed_key.signature.as_bytes())
                .map_err(|_| webpki::Error::UnknownIssuer)?;
            let ext = P2pExtension {
                public_key,
                signature,
            };
            libp2p_extension = Some(ext);
            continue;
        }

        if ext.critical {
            // Endpoints MUST abort the connection attempt if the certificate
            // contains critical extensions that the endpoint does not understand.
            return Err(webpki::Error::UnsupportedCriticalExtension);
        }

        // Implementations MUST ignore non-critical extensions with unknown OIDs.
    }

    // The certificate MUST contain the libp2p Public Key Extension.
    // If this extension is missing, endpoints MUST abort the connection attempt.
    let extension = libp2p_extension.ok_or(webpki::Error::BadDer)?;

    let certificate = P2pCertificate {
        certificate: x509,
        extension,
    };

    Ok(certificate)
}

fn make_libp2p_extension(
    identity_secret_key: &SecretKey,
    certificate_keypair: &rcgen::KeyPair,
) -> Result<rcgen::CustomExtension, rcgen::RcgenError> {
    // The peer signs the concatenation of the string `libp2p-tls-handshake:`
    // and the public key that it used to generate the certificate carrying
    // the libp2p Public Key Extension, using its private host key.
    let signature = {
        let mut msg = vec![];
        msg.extend(P2P_SIGNING_PREFIX);
        msg.extend(certificate_keypair.public_key_der());

        identity_secret_key.sign(&msg)
    };

    let public_key = identity_secret_key.public();
    let public_key_ref = OctetStringRef::new(&public_key.as_bytes()[..])
        .map_err(|_| rcgen::RcgenError::CouldNotParseKeyPair)?;
    let signature = signature.to_bytes();
    let signature_ref =
        OctetStringRef::new(&signature).map_err(|_| rcgen::RcgenError::CouldNotParseCertificate)?;
    let key = SignedKey {
        public_key: public_key_ref,
        signature: signature_ref,
    };

    let mut extension_content = Vec::new();
    key.encode_to_vec(&mut extension_content).expect("vec");

    // This extension MAY be marked critical.
    let mut ext = rcgen::CustomExtension::from_oid_content(&P2P_EXT_OID, extension_content);
    ext.set_criticality(true);

    Ok(ext)
}

impl P2pCertificate<'_> {
    /// The [`PublicKey`] of the remote peer.
    pub fn peer_id(&self) -> PublicKey {
        self.extension.public_key
    }

    /// Verify the `signature` of the `message` signed by the secret key corresponding to the public key stored
    /// in the certificate.
    pub fn verify_signature(
        &self,
        signature_scheme: rustls::SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), VerificationError> {
        let pk = self.public_key(signature_scheme)?;
        pk.verify(message, signature)
            .map_err(|_| webpki::Error::InvalidSignatureForPublicKey)?;

        Ok(())
    }

    /// Get a [`ring::signature::UnparsedPublicKey`] for this `signature_scheme`.
    /// Return `Error` if the `signature_scheme` does not match the public key signature
    /// and hashing algorithm or if the `signature_scheme` is not supported.
    fn public_key(
        &self,
        signature_scheme: rustls::SignatureScheme,
    ) -> Result<ring::signature::UnparsedPublicKey<&[u8]>, webpki::Error> {
        use ring::signature;
        use rustls::SignatureScheme::*;

        let current_signature_scheme = self.signature_scheme()?;
        if signature_scheme != current_signature_scheme {
            // This certificate was signed with a different signature scheme
            return Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey);
        }

        let verification_algorithm: &dyn signature::VerificationAlgorithm = match signature_scheme {
            ECDSA_NISTP256_SHA256 => &signature::ECDSA_P256_SHA256_ASN1,
            ECDSA_NISTP384_SHA384 => &signature::ECDSA_P384_SHA384_ASN1,
            ECDSA_NISTP521_SHA512 => {
                // See https://github.com/briansmith/ring/issues/824
                return Err(webpki::Error::UnsupportedSignatureAlgorithm);
            }
            ED25519 => &signature::ED25519,
            ED448 => {
                // See https://github.com/briansmith/ring/issues/463
                return Err(webpki::Error::UnsupportedSignatureAlgorithm);
            }
            // No support for RSA
            RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384 | RSA_PKCS1_SHA512 | RSA_PSS_SHA256
            | RSA_PSS_SHA384 | RSA_PSS_SHA512 => {
                return Err(webpki::Error::UnsupportedSignatureAlgorithm)
            }
            // Similarly, hash functions with an output length less than 256 bits
            // MUST NOT be used, due to the possibility of collision attacks.
            // In particular, MD5 and SHA1 MUST NOT be used.
            RSA_PKCS1_SHA1 => return Err(webpki::Error::UnsupportedSignatureAlgorithm),
            ECDSA_SHA1_Legacy => return Err(webpki::Error::UnsupportedSignatureAlgorithm),
            Unknown(_) => return Err(webpki::Error::UnsupportedSignatureAlgorithm),
            _ => return Err(webpki::Error::UnsupportedSignatureAlgorithm),
        };
        let spki = &self.certificate.tbs_certificate.subject_pki;
        let key = signature::UnparsedPublicKey::new(
            verification_algorithm,
            spki.subject_public_key.as_ref(),
        );

        Ok(key)
    }

    /// This method validates the certificate according to libp2p TLS 1.3 specs.
    /// The certificate MUST:
    /// 1. be valid at the time it is received by the peer;
    /// 2. use the NamedCurve encoding;
    /// 3. use hash functions with an output length not less than 256 bits;
    /// 4. be self signed;
    /// 5. contain a valid signature in the specific libp2p extension.
    fn verify(&self) -> Result<(), webpki::Error> {
        use webpki::Error;

        // The certificate MUST have NotBefore and NotAfter fields set
        // such that the certificate is valid at the time it is received by the peer.
        if !self.certificate.validity().is_valid() {
            return Err(Error::InvalidCertValidity);
        }

        // Certificates MUST use the NamedCurve encoding for elliptic curve parameters.
        // Similarly, hash functions with an output length less than 256 bits
        // MUST NOT be used, due to the possibility of collision attacks.
        // In particular, MD5 and SHA1 MUST NOT be used.
        // Endpoints MUST abort the connection attempt if it is not used.
        let signature_scheme = self.signature_scheme()?;
        // Endpoints MUST abort the connection attempt if the certificate’s
        // self-signature is not valid.
        let raw_certificate = self.certificate.tbs_certificate.as_ref();
        let signature = self.certificate.signature_value.as_ref();
        // check if self signed
        self.verify_signature(signature_scheme, raw_certificate, signature)
            .map_err(|_| Error::SignatureAlgorithmMismatch)?;

        let subject_pki = self.certificate.public_key().raw;

        // The peer signs the concatenation of the string `libp2p-tls-handshake:`
        // and the public key that it used to generate the certificate carrying
        // the libp2p Public Key Extension, using its private host key.
        let mut msg = vec![];
        msg.extend(P2P_SIGNING_PREFIX);
        msg.extend(subject_pki);

        // This signature provides cryptographic proof that the peer was in possession
        // of the private host key at the time the certificate was signed.
        // Peers MUST verify the signature, and abort the connection attempt
        // if signature verification fails.
        let user_owns_sk = self
            .extension
            .public_key
            .verify(&msg, &self.extension.signature)
            .is_ok();
        if !user_owns_sk {
            return Err(Error::UnknownIssuer);
        }

        Ok(())
    }

    /// Return the signature scheme corresponding to [`AlgorithmIdentifier`]s
    /// of `subject_pki` and `signature_algorithm`
    /// according to <https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3>.
    fn signature_scheme(&self) -> Result<rustls::SignatureScheme, webpki::Error> {
        // Certificates MUST use the NamedCurve encoding for elliptic curve parameters.
        // Endpoints MUST abort the connection attempt if it is not used.
        use oid_registry::*;
        use rustls::SignatureScheme::*;

        let signature_algorithm = &self.certificate.signature_algorithm;
        let pki_algorithm = &self.certificate.tbs_certificate.subject_pki.algorithm;

        if pki_algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
            let signature_param = pki_algorithm
                .parameters
                .as_ref()
                .ok_or(webpki::Error::BadDer)?
                .as_oid()
                .map_err(|_| webpki::Error::BadDer)?;
            if signature_param == OID_EC_P256
                && signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA256
            {
                return Ok(ECDSA_NISTP256_SHA256);
            }
            if signature_param == OID_NIST_EC_P384
                && signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA384
            {
                return Ok(ECDSA_NISTP384_SHA384);
            }
            if signature_param == OID_NIST_EC_P521
                && signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA512
            {
                return Ok(ECDSA_NISTP521_SHA512);
            }
            return Err(webpki::Error::UnsupportedSignatureAlgorithm);
        }

        if signature_algorithm.algorithm == OID_SIG_ED25519 {
            return Ok(ED25519);
        }
        if signature_algorithm.algorithm == OID_SIG_ED448 {
            return Ok(ED448);
        }

        Err(webpki::Error::UnsupportedSignatureAlgorithm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        let secret_key = SecretKey::generate();

        let (cert, _) = generate(&secret_key).unwrap();
        let parsed_cert = parse(&cert).unwrap();

        assert!(parsed_cert.verify().is_ok());
        assert_eq!(secret_key.public(), parsed_cert.extension.public_key);
    }
}
