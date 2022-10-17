use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use thiserror::Error;
use tonic::{
    body::BoxBody,
    transport::{Body, Channel, Endpoint},
};
use tower::Service;

use crate::Addr;

#[derive(Debug, Clone)]
pub struct TonicConnectionPool {
    inner: bb8::Pool<TonicConnectionManager>,
}

impl TonicConnectionPool {
    pub async fn new(max_conns: u32, addr: Addr) -> anyhow::Result<Self> {
        let manager = TonicConnectionManager { addr: addr.clone() };
        let pool = bb8::Pool::builder()
            .max_size(max_conns)
            .build(manager)
            .await
            .unwrap();
        Ok(Self { inner: pool })
    }
}

#[derive(Debug)]
pub struct TonicConnectionManager {
    addr: Addr,
}

#[async_trait]
impl bb8::ManageConnection for TonicConnectionManager {
    type Connection = Channel;
    type Error = ConnectionManagerError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        match self.addr.clone() {
            #[cfg(feature = "grpc")]
            Addr::GrpcHttp2(addr) => {
                let conn = Endpoint::new(format!("http://{}", addr))?
                    .keep_alive_while_idle(true)
                    .connect_lazy();
                return Ok(conn);
            }
            #[cfg(all(feature = "grpc", unix))]
            Addr::GrpcUds(path) => {
                use tokio::net::UnixStream;
                use tonic::transport::Uri;

                let path = std::sync::Arc::new(path);
                // dummy addr
                let conn = Endpoint::new("http://[..]:50051")?
                    .keep_alive_while_idle(true)
                    .connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
                        let path = path.clone();
                        UnixStream::connect(path.as_ref().clone())
                    }));
                return Ok(conn);
            }
            Addr::Mem(_) => {
                return Err(Self::Error::Other(
                    "Mem channels are not supported".to_string(),
                ));
            }
        }
    }

    async fn is_valid(&self, _conn: &mut Self::Connection) -> Result<(), Self::Error> {
        // TODO(arqu): validate working connection
        Ok(())
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}

impl Service<tonic::codegen::http::Request<BoxBody>> for TonicConnectionPool {
    type Response = tonic::codegen::http::Response<Body>;
    type Error = tonic::transport::Error;
    type Future = ResponseFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: tonic::codegen::http::Request<BoxBody>) -> Self::Future {
        let this = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, this);
        // TODO: error handling
        let fut = Box::pin(async move {
            let mut conn = inner.get().await.unwrap();
            Service::call(&mut *conn, request).await
        }); // TODO: avoid box

        ResponseFuture { inner: fut }
    }
}

pub struct ResponseFuture {
    inner: Pin<
        Box<
            dyn Future<
                    Output = Result<tonic::codegen::http::Response<Body>, tonic::transport::Error>,
                > + Send
                + 'static,
        >,
    >,
}

impl Future for ResponseFuture {
    type Output = Result<tonic::codegen::http::Response<Body>, tonic::transport::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

#[derive(Error, Debug)]
pub enum ConnectionManagerError {
    #[error("tonic rpc error: `{0}`")]
    Tonic(#[from] tonic::transport::Error),
    #[error("other connection error: `{0}`")]
    Other(String),
}
