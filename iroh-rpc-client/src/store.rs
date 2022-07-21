use std::io::Cursor;

use anyhow::{Context, Result};
use bytes::Bytes;
use cid::Cid;
use futures::Stream;
use iroh_rpc_types::store::{GetLinksRequest, GetRequest, HasRequest, PutRequest};

use crate::backend::StoreBackend;
use crate::config::Addr;
use crate::status::{self, StatusRow};

#[derive(Debug, Clone)]
pub struct StoreClient {
    backend: StoreBackend,
}

// name that the health service registers the store client as
// this is derived from the protobuf definition of a `StoreServer`
pub const SERVICE_NAME: &str = "store.Store";

// the display name that we expect to see in the StatusTable
pub(crate) const NAME: &str = "store";

impl StoreClient {
    pub async fn new(addr: &Addr) -> Result<Self> {
        match addr {
            Addr::GrpcHttp2(addr) => {
                let backend = StoreBackend::new(*addr)?;

                Ok(StoreClient { backend })
            }
            Addr::GrpcUds(_) => unimplemented!(),
            Addr::Mem => unimplemented!(),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let req = iroh_metrics::req::trace_tonic_req(());
        let res = self.backend.client().clone().version(req).await?;
        Ok(res.into_inner().version)
    }

    #[tracing::instrument(skip(self, blob))]
    pub async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        let req = iroh_metrics::req::trace_tonic_req(PutRequest {
            cid: cid.to_bytes(),
            blob,
            links: links.iter().map(|l| l.to_bytes()).collect(),
        });
        self.backend.client().clone().put(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get(&self, cid: Cid) -> Result<Option<Bytes>> {
        let req = iroh_metrics::req::trace_tonic_req(GetRequest {
            cid: cid.to_bytes(),
        });
        let res = self.backend.client().clone().get(req).await?;
        Ok(res.into_inner().data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn has(&self, cid: Cid) -> Result<bool> {
        let req = iroh_metrics::req::trace_tonic_req(HasRequest {
            cid: cid.to_bytes(),
        });
        let res = self.backend.client().clone().has(req).await?;
        Ok(res.into_inner().has)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>> {
        let req = iroh_metrics::req::trace_tonic_req(GetLinksRequest {
            cid: cid.to_bytes(),
        });
        let links = self
            .backend
            .client()
            .clone()
            .get_links(req)
            .await?
            .into_inner()
            .links;
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

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        status::check(self.backend.health().clone(), SERVICE_NAME, NAME).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        status::watch(self.backend.health().clone(), SERVICE_NAME, NAME).await
    }
}
