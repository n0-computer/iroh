//! Authentication related types and tooling.

use std::future;
use std::pin::Pin;
use std::sync::Arc;
use std::{future::Future, ops::Deref};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::hash::Hash;

/// The error code sent using quinn when aborting due to authentication errors.
pub const REJECTED_CODE: u32 = 10;

#[derive(Debug, Clone)]
pub struct Authenticator(Arc<dyn DynAuthenticator>);

impl Deref for Authenticator {
    type Target = dyn DynAuthenticator;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<A: DynAuthenticator> From<A> for Authenticator {
    fn from(a: A) -> Self {
        Authenticator(Arc::new(a))
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub trait DynAuthenticator: Sync + Send + std::fmt::Debug + 'static {
    /// Optionally add a token to outgoing requests.
    ///
    /// This is called for each outgoing request created by this node.
    /// When returning a `Token`, it will be added to the request payload.
    fn on_outgoing_request(&self, request: Request) -> BoxFuture<Result<Option<Token>>>;

    /// Authenticate incoming requests.
    ///
    /// This is called for each incoming request, right after decoding but before any processing takes place.
    /// Processing and responding only continues if this method returns `AcceptOutcome::Accept`.
    /// Otherwise the request will be declined.
    fn on_incoming_request(
        &self,
        request: Request,
        token: &Option<Token>,
    ) -> BoxFuture<Result<AcceptOutcome>>;
}

#[derive(Debug, Clone)]
pub struct Request {
    /// Identifier to allow correlation with other events related to the request.
    pub id: u64,
    /// Any data related to the request.
    pub data: RequestData,
}

#[derive(Debug, Clone)]
pub enum RequestData {
    Gossip {
        /// Topic ID (raw because of dependencies)
        topic: [u8; 32],
    },
    Bytes(BytesRequestData),
    Sync {
        /// Namespace ID (raw, because of dependencies)
        namespace: [u8; 32],
    },
}

#[derive(Debug, Clone)]
pub enum BytesRequestData {
    Get { hash: Hash },
}

#[derive(Debug, Clone, Copy)]
pub enum AcceptOutcome {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Token {
    /// UUID
    pub id: [u8; 16],
    pub secret: [u8; 32], // set to a sentintel value (all zeros) if no secret present
}

/// A minimal authenticator that does nothing.
#[derive(Debug, Clone)]
pub struct NoAuthenticator;

impl DynAuthenticator for NoAuthenticator {
    fn on_outgoing_request(&self, _request: Request) -> BoxFuture<Result<Option<Token>>> {
        Box::pin(future::ready(Ok(None)))
    }

    fn on_incoming_request(
        &self,
        _request: Request,
        _token: &Option<Token>,
    ) -> BoxFuture<Result<AcceptOutcome>> {
        Box::pin(future::ready(Ok(AcceptOutcome::Accept)))
    }
}
