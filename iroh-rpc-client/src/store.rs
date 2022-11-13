use std::io::Cursor;

use bytes::Bytes;
use cid::Cid;
#[cfg(feature = "grpc")]
use futures::Stream;
#[cfg(feature = "grpc")]
use iroh_rpc_types::store::store_client::StoreClient as GrpcStoreClient;
use iroh_rpc_types::store::{
    GetLinksRequest, GetRequest, GetSizeRequest, HasRequest, PutManyRequest, PutRequest, Store,
    StoreClientAddr, StoreClientBackend,
};
use iroh_rpc_types::Addr;
#[cfg(feature = "grpc")]
use tonic::transport::Endpoint;
#[cfg(feature = "grpc")]
use tonic_health::proto::health_client::HealthClient;

#[cfg(feature = "grpc")]
use crate::status::{self, StatusRow};

use crate::error::Error;

impl_client!(Store);

impl StoreClient {
    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String, Error> {
        let res = self.backend.version(()).await?;
        Ok(res.version)
    }

    #[tracing::instrument(skip(self, blob))]
    pub async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<(), Error> {
        let req = PutRequest {
            cid: cid.to_bytes(),
            blob,
            links: links.iter().map(|l| l.to_bytes()).collect(),
        };
        self.backend.put(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self, blocks))]
    pub async fn put_many(&self, blocks: Vec<(Cid, Bytes, Vec<Cid>)>) -> Result<(), Error> {
        let blocks = blocks
            .into_iter()
            .map(|(cid, blob, links)| PutRequest {
                cid: cid.to_bytes(),
                blob,
                links: links.iter().map(|l| l.to_bytes()).collect(),
            })
            .collect();
        self.backend.put_many(PutManyRequest { blocks }).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get(&self, cid: Cid) -> Result<Option<Bytes>, Error> {
        let req = GetRequest {
            cid: cid.to_bytes(),
        };
        let res = self.backend.get(req).await?;
        Ok(res.data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn has(&self, cid: Cid) -> Result<bool, Error> {
        let req = HasRequest {
            cid: cid.to_bytes(),
        };
        let res = self.backend.has(req).await?;
        Ok(res.has)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>, Error> {
        let req = GetLinksRequest {
            cid: cid.to_bytes(),
        };
        let links = self.backend.get_links(req).await?.links;
        if links.is_empty() {
            Ok(None)
        } else {
            let links: Result<Vec<Cid>, Error> = links
                .iter()
                .map(|l| Cid::read_bytes(Cursor::new(l)).map_err(Error::from))
                .collect();
            Ok(Some(links?))
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_size(&self, cid: Cid) -> Result<Option<u64>, Error> {
        let req = GetSizeRequest {
            cid: cid.to_bytes(),
        };
        let size = self.backend.get_size(req).await?.size;
        Ok(size)
    }
}
