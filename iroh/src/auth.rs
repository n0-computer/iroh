//! Authenticator tooling.

use std::future;

use anyhow::Result;
use futures::future::BoxFuture;
use iroh_base::auth::{AcceptOutcome, DynAuthenticator, Request, RequestData, Token};

/// A minimal authenticator that only tracks IDs
#[derive(Debug, Clone)]
pub struct IdAuthenticator {
    id: [u8; 16],
}

impl IdAuthenticator {
    /// Constructs a new IdAuthenticator with the provided uuid.
    pub fn new(id: [u8; 16]) -> Self {
        IdAuthenticator { id }
    }
}

impl DynAuthenticator for IdAuthenticator {
    fn request(&self, _request: Request) -> BoxFuture<'static, Result<Option<Token>>> {
        Box::pin(future::ready(Ok(Some(Token {
            id: self.id,
            secret: [0u8; 32],
        }))))
    }

    fn respond(
        &self,
        request: Request,
        token: &Option<Token>,
    ) -> BoxFuture<'static, Result<AcceptOutcome>> {
        if let Some(token) = token {
            match request.data {
                RequestData::Bytes(_) => {
                    tracing::debug!("auth:bytes:{}", hex::encode(&token.id));
                }
                RequestData::Gossip { .. } => {
                    tracing::debug!("auth:gossip:{}", hex::encode(&token.id));
                }
                RequestData::Sync { .. } => {
                    tracing::debug!("auth:sync:{}", hex::encode(&token.id));
                }
            }
        }

        Box::pin(future::ready(Ok(AcceptOutcome::Accept)))
    }
}
