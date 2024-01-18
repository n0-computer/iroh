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
        tracing::info!("auth:new {}", hex::encode(id));
        IdAuthenticator { id }
    }
}

impl DynAuthenticator for IdAuthenticator {
    fn on_outgoing_request(&self, _request: Request) -> BoxFuture<'static, Result<Option<Token>>> {
        tracing::info!("auth:request {}", hex::encode(self.id));
        Box::pin(future::ready(Ok(Some(Token {
            id: self.id,
            secret: [0u8; 32],
        }))))
    }

    fn on_incoming_request(
        &self,
        request: Request,
        token: &Option<Token>,
    ) -> BoxFuture<'static, Result<AcceptOutcome>> {
        if let Some(token) = token {
            match request.data {
                RequestData::Bytes(_) => {
                    tracing::info!("auth:bytes:{}", hex::encode(token.id));
                }
                RequestData::Gossip { .. } => {
                    tracing::info!("auth:gossip:{}", hex::encode(token.id));
                }
                RequestData::Sync { .. } => {
                    tracing::info!("auth:sync:{}", hex::encode(token.id));
                }
            }
        }

        Box::pin(future::ready(Ok(AcceptOutcome::Accept)))
    }
}
