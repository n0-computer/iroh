use async_trait::async_trait;
use tonic::{transport::{Channel, Endpoint}};

use crate::Addr;

#[derive(Debug, Clone)]
pub struct TonicConnectionPool {
    inner: r2d2::Pool<TonicConnectionManager>,
}

impl TonicConnectionPool {
    pub fn new(max_conns: u32, addr: Addr) -> anyhow::Result<Self> {
        let manager = TonicConnectionManager{addr: addr.clone()};
        let pool = r2d2::Pool::builder().max_size(max_conns).build(manager).unwrap();
        Ok(Self { inner: pool })
    }
}

#[derive(Debug)]
pub struct TonicConnectionManager {
    addr: Addr,
}

#[async_trait]
impl r2d2::ManageConnection for TonicConnectionManager {
    type Connection = Channel;
    type Error = ConnectionManagerError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
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

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        // conn.execute_batch("").map_err(Into::into)
        Ok(())
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
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
