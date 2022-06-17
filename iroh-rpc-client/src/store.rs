use std::io::Cursor;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use bytes::Bytes;
use cid::Cid;
use futures::Stream;
use iroh_rpc_types::store::{
    self, GetLinksRequest, GetP2pIdentityRequest, GetRequest, HasRequest, PutP2pIdentityRequest,
    PutRequest,
};
use libp2p::identity::Keypair;
use tonic::transport::{Channel, Endpoint};
use tonic_health::proto::health_client::HealthClient;

use crate::status::{self, StatusRow};

#[derive(Debug, Clone)]
pub struct StoreClient {
    store: store::store_client::StoreClient<Channel>,
    health: HealthClient<Channel>,
}

// name that the health service registers the store client as
// this is derived from the protobuf definition of a `StoreServer`
pub const SERVICE_NAME: &str = "store.Store";

// the display name that we expect to see in the StatusTable
pub(crate) const NAME: &str = "store";

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
        let res = self.store.clone().has(req).await?;
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
    pub async fn get_p2p_identity(&self) -> Result<Option<Keypair>> {
        let req = iroh_metrics::req::trace_tonic_req(GetP2pIdentityRequest {});
        let res = self.store.clone().get_p2p_identity(req).await?;

        if let Some(raw) = res.into_inner().keypair {
            if !raw.is_empty() {
                let keypair = Keypair::from_protobuf_encoding(&raw)?;
                return Ok(Some(keypair));
            }
        }

        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    pub async fn put_p2p_identity(&self, keypair: &Keypair) -> Result<()> {
        let req = iroh_metrics::req::trace_tonic_req(PutP2pIdentityRequest {
            keypair: keypair.to_protobuf_encoding()?,
        });
        self.store.clone().put_p2p_identity(req).await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        status::check(self.health.clone(), SERVICE_NAME, NAME).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        status::watch(self.health.clone(), SERVICE_NAME, NAME).await
    }
}
