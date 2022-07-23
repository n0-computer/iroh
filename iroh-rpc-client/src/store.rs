use std::io::Cursor;

use anyhow::{Context, Result};
use bytes::Bytes;
use cid::Cid;
use futures::Stream;
#[cfg(feature = "grpc")]
use iroh_rpc_types::store::store_client::StoreClient as GrpcStoreClient;
use iroh_rpc_types::store::{GetLinksRequest, GetRequest, HasRequest, PutRequest, Store};
use iroh_rpc_types::Addr;
#[cfg(feature = "grpc")]
use tonic::transport::{Channel, Endpoint};
#[cfg(feature = "grpc")]
use tonic_health::proto::health_client::HealthClient;

#[cfg(feature = "grpc")]
use crate::status::{self, StatusRow};

// name that the health service registers the store client as
// this is derived from the protobuf definition of a `StoreServer`
pub const SERVICE_NAME: &str = "store.Store";

// the display name that we expect to see in the StatusTable
pub(crate) const NAME: &str = "store";

#[derive(Debug, Clone)]
pub enum StoreClient {
    #[cfg(feature = "grpc")]
    Grpc {
        client: GrpcStoreClient<Channel>,
        health: HealthClient<Channel>,
    },
    #[cfg(feature = "mem")]
    Mem,
}

impl StoreClient {
    pub async fn new(addr: &Addr) -> Result<Self> {
        match addr {
            #[cfg(feature = "grpc")]
            Addr::GrpcHttp2(addr) => {
                let conn = Endpoint::new(format!("http://{}", addr))?
                    .keep_alive_while_idle(true)
                    .connect_lazy();

                let client = GrpcStoreClient::new(conn.clone());
                let health = HealthClient::new(conn);

                Ok(StoreClient::Grpc { client, health })
            }
            #[cfg(feature = "grpc")]
            Addr::GrpcUds(_) => unimplemented!(),
            #[cfg(feature = "mem")]
            Addr::Mem => Ok(StoreClient::Mem),
        }
    }

    fn backend(&self) -> &impl Store {
        match self {
            #[cfg(feature = "grpc")]
            Self::Grpc { client, .. } => client,
            #[cfg(feature = "mem")]
            Self::Mem => {
                todo!()
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.backend().version(()).await?;
        Ok(res.version)
    }

    #[cfg(feature = "grpc")]
    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        match self {
            Self::Grpc { health, .. } => status::check(health.clone(), SERVICE_NAME, NAME).await,
            Self::Mem => {
                todo!()
            }
        }
    }

    #[cfg(feature = "grpc")]
    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        match self {
            Self::Grpc { health, .. } => status::watch(health.clone(), SERVICE_NAME, NAME).await,
            Self::Mem => {
                todo!()
            }
        }
    }

    #[tracing::instrument(skip(self, blob))]
    pub async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        let req = PutRequest {
            cid: cid.to_bytes(),
            blob,
            links: links.iter().map(|l| l.to_bytes()).collect(),
        };
        self.backend().put(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get(&self, cid: Cid) -> Result<Option<Bytes>> {
        let req = GetRequest {
            cid: cid.to_bytes(),
        };
        let res = self.backend().get(req).await?;
        Ok(res.data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn has(&self, cid: Cid) -> Result<bool> {
        let req = HasRequest {
            cid: cid.to_bytes(),
        };
        let res = self.backend().has(req).await?;
        Ok(res.has)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>> {
        let req = GetLinksRequest {
            cid: cid.to_bytes(),
        };
        let links = self.backend().get_links(req).await?.links;
        if links.is_empty() {
            Ok(None)
        } else {
            let links: Result<Vec<Cid>> = links
                .iter()
                .map(|l| Cid::read_bytes(Cursor::new(l)).context(format!("invalid cid: {:?}", l)))
                .collect();
            Ok(Some(links?))
        }
    }
}
