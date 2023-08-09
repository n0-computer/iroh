use std::sync::Arc;

use iroh::{
    bytes::util::runtime::Handle,
    client::Doc as ClientDoc,
    database::flat,
    net::tls::Keypair,
    node::{Node, DEFAULT_BIND_ADDR},
    rpc_protocol::{ProviderRequest, ProviderResponse, ProviderService},
};
use quic_rpc::transport::flume::FlumeConnection;

use crate::error::{IrohError as Error, Result};

pub struct Doc(ClientDoc<FlumeConnection<ProviderResponse, ProviderRequest>>);

impl Doc {
    pub fn id(&self) -> String {
        self.0.id().to_string()
    }
}

pub struct IrohNode(Arc<Inner>);

struct Inner {
    node: Node<flat::Database, iroh_sync::store::fs::Store>,
    async_runtime: Handle,
    sync_client: iroh::client::Iroh<FlumeConnection<ProviderResponse, ProviderRequest>>,
    tokio_rt: tokio::runtime::Runtime,
}

impl IrohNode {
    pub fn new() -> Result<Self> {
        let tokio_rt = tokio::runtime::Builder::new_multi_thread()
            .thread_name("main-runtime")
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| Error::Runtime(e.to_string()))?;

        let tpc = tokio_util::task::LocalPoolHandle::new(num_cpus::get());
        let rt = iroh::bytes::util::runtime::Handle::new(tokio_rt.handle().clone(), tpc);

        // TODO: pass in path
        let path = tempfile::tempdir()
            .map_err(|e| Error::NodeCreate(e.to_string()))?
            .into_path();

        let db = flat::Database::default();

        // TODO: store and load keypair
        let keypair = Keypair::generate();

        let rt_inner = rt.clone();
        let node = rt
            .main()
            .block_on(async move {
                let store = iroh_sync::store::fs::Store::new(path.join("sync.db"))?;
                let path = path.join("blobs_dir");

                Node::builder(db, store, path)
                    .bind_addr(DEFAULT_BIND_ADDR.into())
                    .keypair(keypair)
                    .runtime(&rt_inner)
                    .spawn()
                    .await
            })
            .map_err(|e| Error::NodeCreate(e.to_string()))?;

        let sync_client = node.client();

        Ok(IrohNode(Arc::new(Inner {
            node,
            async_runtime: rt,
            sync_client,
            tokio_rt,
        })))
    }

    pub fn peer_id(&self) -> String {
        self.0.node.peer_id().to_string()
    }

    pub fn sync_create_doc(&self) -> Result<Arc<Doc>> {
        let doc = self
            .0
            .async_runtime
            .main()
            .block_on(async { self.0.sync_client.create_doc().await })
            .map_err(|e| Error::Doc(e.to_string()))?;

        Ok(Arc::new(Doc(doc)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doc_create() {
        let node = IrohNode::new().unwrap();
        let peer_id = node.peer_id();
        println!("id: {}", peer_id);
        let doc = node.sync_create_doc().unwrap();
        let doc_id = doc.id();
        println!("doc_id: {}", doc_id);
    }
}
