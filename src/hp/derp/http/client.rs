//! Based on tailscale/derp/derphttp/derphttp_client.go
use std::net::SocketAddr;

use anyhow::Result;
use futures::future::BoxFuture;

use crate::hp::key;

use crate::hp::derp::{DerpRegion, ReceivedMessage};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("todo")]
    Todo,
    #[error("closed")]
    Closed,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Client {}

impl Client {
    pub fn new_region<F>(key: key::node::SecretKey, f: F) -> Self
    where
        F: Fn() -> BoxFuture<'static, Option<DerpRegion>>,
    {
        // TODO:
        Client {}
    }

    pub fn set_can_ack_pings(&self, val: bool) {
        // TODO:
    }

    pub fn note_preferred(&self, is_preferred: bool) {
        // TODO:
    }

    // S returns if we should prefer ipv6
    // it replaces the derphttp.AddressFamilySelector we pass
    // It provides the hint as to whether in an IPv4-vs-IPv6 race that
    // IPv4 should be held back a bit to give IPv6 a better-than-50/50
    // chance of winning. We only return true when we believe IPv6 will
    // work anyway, so we don't artificially delay the connection speed.
    pub fn set_address_family_selector<S>(&self, selector: S)
    where
        S: Fn() -> BoxFuture<'static, bool>,
    {
        // TODO.
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        // TODO:
        None
    }
    pub async fn ping(&self) -> Result<(), ClientError> {
        Err(ClientError::Todo)
    }

    pub async fn send_pong(&self, data: [u8; 8]) -> Result<(), ClientError> {
        Err(ClientError::Todo)
    }
    pub async fn recv_detail(&self) -> Result<(ReceivedMessage, usize), ClientError> {
        Err(ClientError::Todo)
    }

    pub async fn send(
        &self,
        dst_key: Option<key::node::PublicKey>,
        b: Vec<u8>,
    ) -> Result<(), ClientError> {
        Err(ClientError::Todo)
    }

    pub async fn close(self) {
        // TODO
    }
}
