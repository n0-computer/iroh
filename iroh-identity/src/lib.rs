//! Shared experimental identity credentials and verification for iroh protocols.
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

mod crypto;
mod trust;
pub use crypto::{
    BuiltinAlgorithm, IdentityAlgorithm, LocalIdentity, PeerId, Registry, RemotePolicy, SecretBytes,
};
pub use trust::TrustStore;

/// Errors from identity configuration, parsing, or connection establishment.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Unknown version, malformed ID, or an invalid conversion to a legacy ID.
    #[error("invalid or unsupported identity encoding")]
    Encoding,
    /// The requested suite is not registered or permitted.
    #[error("unsupported or disallowed identity suite")]
    Suite,
    /// Two adapters claim the same suite or TLS signature scheme.
    #[error("duplicate identity suite registration")]
    DuplicateSuite,
    /// Malformed, ambiguous, oversized or unsupported public key material.
    #[error("invalid public identity")]
    PublicIdentity,
    /// The peer presented a different identity from the one requested.
    #[error("the authenticated identity differs from the expected identity")]
    IdentityMismatch,
    /// The signer does not provide the required public key or signature scheme.
    #[error("signer does not provide a supported public key and signature scheme")]
    Signer,
    /// The cryptographic backend failed to generate a signing key.
    #[error("key generation failed")]
    KeyGeneration,
    /// The TLS provider cannot supply a QUIC token key.
    #[error("invalid crypto provider")]
    Provider,
    /// An ALPN must contain between one and 255 bytes.
    #[error("invalid ALPN length")]
    Alpn,
    /// A concrete local binding must be selected before binding the endpoint.
    #[error("bind_addr must be configured")]
    BindAddr,
    /// The destination has no usable IP address or port.
    #[error("a concrete destination IP address and nonzero port are required")]
    Destination,
    /// The requested destination identity is our own identity.
    #[error("cannot connect to our own identity")]
    SelfConnect,
    /// TLS configuration or authentication failed.
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    /// Socket binding or inspection failed.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    /// QUIC requires a cipher suite unavailable in the provider.
    #[error("QUIC configuration: {0}")]
    QuicConfig(#[from] noq::crypto::rustls::NoInitialCipherSuite),
    /// QUIC could not start connecting.
    #[error("QUIC connect: {0}")]
    Connect(#[from] noq::ConnectError),
    /// The handshake or connection failed.
    #[error("QUIC connection: {0}")]
    Connection(#[from] noq::ConnectionError),
    /// The endpoint no longer accepts connections.
    #[error("endpoint is closed")]
    Closed,
    /// The peer is not in the explicitly configured identity allowlist.
    #[error("identity is not authorized")]
    Unauthorized,
    /// The credential was supplied by a signer that does not export its key.
    #[error("credential is not exportable")]
    NonExportable,
    /// A key file is accessible to other users on Unix.
    #[error("key file permissions must exclude group and other access")]
    InsecureKeyFile,
    /// A versioned protocol message failed validation.
    #[error("invalid identity protocol message: {0}")]
    Protocol(&'static str),
    /// A trust update did not match the application's current pin.
    #[error("trust update does not match the current pin")]
    TrustMismatch,
}
