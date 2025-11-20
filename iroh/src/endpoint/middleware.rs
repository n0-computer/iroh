#![allow(missing_docs)]

use std::pin::Pin;

use iroh_base::EndpointAddr;
use quinn::VarInt;

use crate::endpoint::connection::ConnectionInfo;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
pub enum BeforeConnectOutcome {
    Accept,
    Reject,
}

#[derive(Debug)]
pub enum AfterHandshakeOutcome {
    Accept,
    Reject { error_code: VarInt, reason: Vec<u8> },
}

impl AfterHandshakeOutcome {
    pub fn accept() -> Self {
        Self::Accept
    }

    pub fn close(&self, error_code: VarInt, reason: &[u8]) -> Self {
        Self::Reject {
            error_code,
            reason: reason.to_vec(),
        }
    }
}

pub trait Middleware: std::fmt::Debug + Send + Sync {
    fn before_connect<'a>(
        &'a self,
        _remote_addr: &'a EndpointAddr,
        _alpn: &'a [u8],
    ) -> impl Future<Output = BeforeConnectOutcome> + Send + 'a {
        async { BeforeConnectOutcome::Accept }
    }

    fn handshake_completed<'a>(
        &'a self,
        _conn: &'a ConnectionInfo,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        async { AfterHandshakeOutcome::accept() }
    }
}

pub(crate) trait DynMiddleware: std::fmt::Debug + Send + Sync {
    fn before_connect<'a>(
        &'a self,
        _remote_addr: &'a EndpointAddr,
        _alpn: &'a [u8],
    ) -> BoxFuture<'a, BeforeConnectOutcome>;
    fn handshake_completed<'a>(
        &'a self,
        _conn: &'a ConnectionInfo,
    ) -> BoxFuture<'a, AfterHandshakeOutcome>;
}

impl<T: Middleware> DynMiddleware for T {
    fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BoxFuture<'a, BeforeConnectOutcome> {
        Box::pin(Middleware::before_connect(self, remote_addr, alpn))
    }

    fn handshake_completed<'a>(
        &'a self,
        conn: &'a ConnectionInfo,
    ) -> BoxFuture<'a, AfterHandshakeOutcome> {
        Box::pin(Middleware::handshake_completed(self, conn))
    }
}

#[derive(Debug, Default)]
pub(crate) struct MiddlewareList {
    inner: Vec<Box<dyn DynMiddleware>>,
}

impl MiddlewareList {
    pub(super) fn push(&mut self, middleware: impl Middleware + 'static) {
        let middleware: Box<dyn DynMiddleware> = Box::new(middleware);
        self.inner.push(middleware);
    }

    pub(super) async fn before_connect(
        &self,
        remote_addr: &EndpointAddr,
        alpn: &[u8],
    ) -> BeforeConnectOutcome {
        for middleware in self.inner.iter() {
            match middleware.before_connect(remote_addr, alpn).await {
                BeforeConnectOutcome::Accept => continue,
                reject @ BeforeConnectOutcome::Reject => return reject,
            }
        }
        BeforeConnectOutcome::Accept
    }

    pub(super) async fn handshake_completed(&self, conn: &ConnectionInfo) -> AfterHandshakeOutcome {
        for middleware in self.inner.iter() {
            match middleware.handshake_completed(conn).await {
                AfterHandshakeOutcome::Accept => continue,
                reject @ AfterHandshakeOutcome::Reject { .. } => return reject,
            }
        }
        AfterHandshakeOutcome::Accept
    }
}
