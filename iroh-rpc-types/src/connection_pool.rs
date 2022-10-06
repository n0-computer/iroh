use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use tonic::{
    body::BoxBody,
    client::GrpcService,
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

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        // conn.execute_batch("").map_err(Into::into)
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
        // TODO: async
        // TODO: error handling
        let h = tokio::spawn(async move {
            let conn = &mut *self.inner.get().await.unwrap();
            let inner = Service::call(conn, request);

            ResponseFuture { inner }
        });
        ResponseFuture { inner: h }
    }
}

pub struct ResponseFuture {
    inner: tonic::transport::channel::ResponseFuture,
}

impl Future for ResponseFuture {
    type Output = Result<tonic::codegen::http::Response<Body>, tonic::transport::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ConnectionManagerError {
        Tonic(err: tonic::transport::Error) {
            from()
        }
        Other(err: String) {
            from()
        }
    }
}
