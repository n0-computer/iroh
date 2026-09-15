//! Native tests for the additive identity API.
#![cfg(all(feature = "unstable-identity", not(target_family = "wasm")))]

#[path = "identity/binding.rs"]
mod binding;
#[path = "identity/client_auth.rs"]
mod client_auth;
#[path = "identity/encoding.rs"]
mod encoding;
#[path = "identity/handshake.rs"]
mod handshake;
#[path = "identity/interop.rs"]
mod interop;
#[path = "identity/policy.rs"]
mod policy;
#[path = "identity/relay.rs"]
mod relay;
#[path = "identity/released.rs"]
mod released;
