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
    fn request(&self, request: Request) -> BoxFuture<Result<Option<Token>>>;
    fn respond(&self, request: Request, token: &Option<Token>) -> BoxFuture<Result<AcceptOutcome>>;
}

/// A minimal authenticator that does nothing.
#[derive(Debug, Clone)]
pub struct NoAuthenticator;

impl DynAuthenticator for NoAuthenticator {
    fn request(&self, _request: Request) -> BoxFuture<Result<Option<Token>>> {
        Box::pin(future::ready(Ok(None)))
    }

    fn respond(
        &self,
        _request: Request,
        _token: &Option<Token>,
    ) -> BoxFuture<Result<AcceptOutcome>> {
        Box::pin(future::ready(Ok(AcceptOutcome::Accept)))
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub id: u64,
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
