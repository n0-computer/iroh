use anyhow::Result;
use iroh_blobs::protocol::ALPN;
use iroh_net::{endpoint::Connection, Endpoint, NodeId};

use crate::{
    actor::ActorHandle,
    net,
    session::{Role, SessionInit},
    store::memory,
};

#[derive(Debug, Clone)]
pub struct Engine {
    endpoint: Endpoint,
    handle: ActorHandle,
}

impl Engine {
    pub fn new(endpoint: Endpoint, handle: ActorHandle) -> Self {
        Self { endpoint, handle }
    }

    pub fn memory(endpoint: Endpoint) -> Self {
        let me = endpoint.node_id();
        let payloads = iroh_blobs::store::mem::Store::default();
        let handle = ActorHandle::spawn(move || memory::Store::new(payloads), me);
        Self::new(endpoint, handle)
    }

    pub async fn handle_connection(&self, conn: Connection, init: SessionInit) -> Result<()> {
        let our_role = Role::Betty;
        let handle = self.handle.clone();
        let mut session = net::run(self.endpoint.node_id(), handle, conn, our_role, init).await?;
        session.join().await?;
        Ok(())
    }

    pub async fn sync_with_peer(&self, peer: NodeId, init: SessionInit) -> Result<()> {
        let our_role = Role::Alfie;
        let conn = self.endpoint.connect_by_node_id(&peer, ALPN).await?;
        let handle = self.handle.clone();
        let mut session = net::run(self.endpoint.node_id(), handle, conn, our_role, init).await?;
        session.join().await?;
        Ok(())
    }
}
