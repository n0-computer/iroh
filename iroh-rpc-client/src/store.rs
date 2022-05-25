use std::io::Cursor;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use bytes::Bytes;
use cid::Cid;
use iroh_rpc_types::store::{self, GetLinksRequest, GetRequest, HasRequest, PutRequest};

use tonic::{
    codec::Streaming,
    transport::{Channel, Endpoint},
};

use tonic_health::proto::{
    health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
    HealthCheckResponse,
};

#[derive(Debug, Clone)]
pub struct StoreClient {
    store: store::store_client::StoreClient<Channel>,
    health: HealthClient<Channel>,
}

impl StoreClient {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let conn = Endpoint::new(format!("http://{}", addr))?
            .keep_alive_while_idle(true)
            .connect_lazy();

        let client = store::store_client::StoreClient::new(conn.clone());
        let health = HealthClient::new(conn);

        Ok(StoreClient {
            store: client,
            health,
        })
    }

    #[tracing::instrument(skip(self, blob))]
    pub async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        let req = iroh_metrics::req::trace_tonic_req(PutRequest {
            cid: cid.to_bytes(),
            blob,
            links: links.iter().map(|l| l.to_bytes()).collect(),
        });
        self.store.clone().put(req).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get(&self, cid: Cid) -> Result<Option<Bytes>> {
        let req = iroh_metrics::req::trace_tonic_req(GetRequest {
            cid: cid.to_bytes(),
        });
        let res = self.store.clone().get(req).await?;
        Ok(res.into_inner().data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn has(&self, cid: Cid) -> Result<bool> {
        let req = iroh_metrics::req::trace_tonic_req(HasRequest {
            cid: cid.to_bytes(),
        });
        let res = self.0.clone().has(req).await?;
        Ok(res.into_inner().has)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>> {
        let req = iroh_metrics::req::trace_tonic_req(GetLinksRequest {
            cid: cid.to_bytes(),
        });
        let links = self.store.clone().get_links(req).await?.into_inner().links;
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
    pub async fn check(&self) -> Result<ServingStatus> {
        let req = iroh_metrics::req::trace_tonic_req(HealthCheckRequest { service: "".into() });
        let res = self.health.clone().check(req).await?.into_inner();
        Ok(res.status())
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> Result<Streaming<HealthCheckResponse>> {
        let req = iroh_metrics::req::trace_tonic_req(HealthCheckRequest { service: "".into() });
        let res = self.health.clone().watch(req).await?.into_inner();
        Ok(res)
    }
}
