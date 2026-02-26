use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey};
use iroh_base::EndpointId;
use tracing::warn;

use crate::endpoint::RemoteEndpointIdError;

/// Strategy for extracting a remote [`EndpointId`] from a QUIC connection.
///
/// After a TLS handshake completes, the peer's identity must be derived from
/// the certificate(s) presented during the handshake.  Implementations of this
/// trait define *how* that derivation works, allowing different TLS
/// configurations (e.g. raw public keys vs. X.509 certificates) to plug in
/// their own logic.
///
/// See [`RawEd25519Id`] for the default implementation used by standard iroh
/// endpoints.
pub trait IdFromQuinnConn: std::fmt::Debug + Send + Sync {
    /// Extract the remote peer's [`EndpointId`] from an established QUIC
    /// connection.
    ///
    /// Called after the TLS handshake succeeds.  The implementation should
    /// inspect [`quinn::Connection::peer_identity`] to obtain the peer's
    /// certificate chain and derive a stable 32-byte identifier from it.
    fn remote_id_from_quinn_conn(
        &self,
        conn: &quinn::Connection,
    ) -> Result<EndpointId, RemoteEndpointIdError>;
}

/// Default [`IdFromQuinnConn`] implementation for standard iroh endpoints.
///
/// Expects exactly one certificate entry containing a DER-encoded Ed25519
/// SPKI (SubjectPublicKeyInfo, per RFC 7250 raw public keys) and converts
/// it directly into an [`EndpointId`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RawEd25519Id;

impl IdFromQuinnConn for RawEd25519Id {
    fn remote_id_from_quinn_conn(
        &self,
        conn: &quinn::Connection,
    ) -> Result<EndpointId, RemoteEndpointIdError> {
        let data = conn.peer_identity();

        match data {
            None => {
                warn!("no peer certificate found");
                Err(RemoteEndpointIdError::new())
            }

            Some(data) => match data.downcast::<Vec<rustls::pki_types::CertificateDer>>() {
                Ok(certs) => {
                    if certs.len() != 1 {
                        warn!(
                            "expected a single peer certificate, but {} found",
                            certs.len()
                        );
                        return Err(RemoteEndpointIdError::new());
                    }

                    let peer_id = EndpointId::from_verifying_key(
                        VerifyingKey::from_public_key_der(&certs[0])
                            .map_err(|_| RemoteEndpointIdError::new())?,
                    );

                    Ok(peer_id)
                }

                Err(err) => {
                    warn!("invalid peer certificate: {:?}", err);
                    Err(RemoteEndpointIdError::new())
                }
            },
        }
    }
}
