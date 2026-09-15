//! Pluggable endpoint identities, available with `unstable-identity` on native targets.
//!
//! The normal endpoint builder's `credentials` method selects this typed API.
//! It supports Ed25519 and ML-DSA-65 authentication, direct IP and versioned relay
//! routing, key persistence and explicit trust migration.
//! QUIC performs authenticated NAT traversal without changing the peer identity.
//! The native API and `iroh-pid1-` encoding are experimental and are not covered
//! by semantic versioning guarantees. Session resumption is disabled.
//!
//! Existing [`crate::Endpoint`] and [`crate::EndpointId`] APIs are unchanged.
//! A new [`PeerId`] must be authenticated exactly; dialing it never falls back
//! to a legacy identity. Each endpoint has one local identity. Applications
//! serving both identity types can bind two endpoint instances.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use iroh::{Endpoint, endpoint::presets::Empty};
//! use iroh::identity::{LocalIdentity, Registry, RemotePolicy};
//!
//! let registry = Arc::new(Registry::builtins(vec![2])?); // ML-DSA-65 only
//! let identity = LocalIdentity::generate_ml_dsa65(&registry)?;
//! let endpoint = Endpoint::builder(Empty).credentials(identity, registry)
//!     .remote_policy(RemotePolicy::new([2]))
//!     .bind_addr("127.0.0.1:0".parse()?)
//!     .alpns(vec![b"my-protocol/1".to_vec()])
//!     .bind().await?;
//! println!("{} at {}", endpoint.id(), endpoint.local_addr()?);
//! endpoint.close().await;
//! # Ok(()) }
//! ```

pub(crate) mod endpoint;
mod paths;
mod routing;
mod tls;

pub use endpoint::{Builder, Connection, EndpointAddr, IdentityEndpoint};
pub use iroh_identity::{
    BuiltinAlgorithm, Error, IdentityAlgorithm, LocalIdentity, PeerId, Registry, RemotePolicy,
    SecretBytes, TrustStore,
};
