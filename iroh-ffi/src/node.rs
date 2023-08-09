use std::sync::Arc;

use futures::stream::TryStreamExt;
use iroh::{
    bytes::util::runtime::Handle,
    client::Doc as ClientDoc,
    database::flat,
    net::tls::Keypair,
    node::{Node, DEFAULT_BIND_ADDR},
    rpc_protocol::{ProviderRequest, ProviderResponse, ShareMode},
};
use iroh_sync::store::{GetFilter, KeyFilter};
use quic_rpc::transport::flume::FlumeConnection;

use crate::error::{IrohError as Error, Result};

pub struct SignedEntry(iroh_sync::sync::SignedEntry);

impl SignedEntry {
    pub fn author(&self) -> Arc<AuthorId> {
        Arc::new(AuthorId(self.0.author()))
    }

    pub fn key(&self) -> Vec<u8> {
        self.0.key().to_vec()
    }
}

pub struct Doc {
    inner: ClientDoc<FlumeConnection<ProviderResponse, ProviderRequest>>,
    rt: Handle,
}

impl Doc {
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    pub fn latest(&self) -> Result<Vec<Arc<SignedEntry>>> {
        let latest = self
            .rt
            .main()
            .block_on(async {
                let get_result = self
                    .inner
                    .get(GetFilter {
                        latest: true,
                        author: None,
                        key: KeyFilter::All,
                    })
                    .await?;
                get_result
                    .map_ok(|e| Arc::new(SignedEntry(e)))
                    .try_collect::<Vec<_>>()
                    .await
            })
            .map_err(|e| Error::Doc(e.to_string()))?;
        Ok(latest)
    }

    pub fn share_write(&self) -> Result<Arc<DocTicket>> {
        let ticket = self
            .rt
            .main()
            .block_on(async { self.inner.share(ShareMode::Write).await })
            .map_err(|e| Error::Doc(e.to_string()))?;

        Ok(Arc::new(DocTicket(ticket)))
    }

    pub fn share_read(&self) -> Result<Arc<DocTicket>> {
        let ticket = self
            .rt
            .main()
            .block_on(async { self.inner.share(ShareMode::Read).await })
            .map_err(|e| Error::Doc(e.to_string()))?;

        Ok(Arc::new(DocTicket(ticket)))
    }

    pub fn set_bytes(
        &self,
        author_id: Arc<AuthorId>,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<Arc<SignedEntry>> {
        let entry = self
            .rt
            .main()
            .block_on(async { self.inner.set_bytes(author_id.0.clone(), key, value).await })
            .map_err(|e| Error::Doc(e.to_string()))?;

        Ok(Arc::new(SignedEntry(entry)))
    }

    pub fn get_content_bytes(&self, entry: Arc<SignedEntry>) -> Result<Vec<u8>> {
        let content = self
            .rt
            .main()
            .block_on(async { self.inner.get_content_bytes(&entry.0).await })
            .map_err(|e| Error::Doc(e.to_string()))?;

        Ok(content.to_vec())
    }
}

pub struct AuthorId(iroh_sync::sync::AuthorId);

impl AuthorId {
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DocTicket(iroh::rpc_protocol::DocTicket);

impl DocTicket {
    pub fn from_string(content: String) -> Result<Self> {
        let ticket = content
            .parse::<iroh::rpc_protocol::DocTicket>()
            .map_err(|e| Error::DocTicket(e.to_string()))?;
        Ok(DocTicket(ticket))
    }

    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

pub struct IrohNode {
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

        Ok(IrohNode {
            node,
            async_runtime: rt,
            sync_client,
            tokio_rt,
        })
    }

    pub fn peer_id(&self) -> String {
        self.node.peer_id().to_string()
    }

    pub fn create_doc(&self) -> Result<Arc<Doc>> {
        let doc = self
            .async_runtime
            .main()
            .block_on(async { self.sync_client.create_doc().await })
            .map_err(|e| Error::Doc(e.to_string()))?;

        Ok(Arc::new(Doc {
            inner: doc,
            rt: self.async_runtime.clone(),
        }))
    }

    pub fn create_author(&self) -> Result<Arc<AuthorId>> {
        let author = self
            .async_runtime
            .main()
            .block_on(async { self.sync_client.create_author().await })
            .map_err(|e| Error::Author(e.to_string()))?;

        Ok(Arc::new(AuthorId(author)))
    }

    pub fn import_doc(&self, ticket: Arc<DocTicket>) -> Result<Arc<Doc>> {
        let doc = self
            .async_runtime
            .main()
            .block_on(async { self.sync_client.import_doc(ticket.0.clone()).await })
            .map_err(|e| Error::Doc(e.to_string()))?;

        Ok(Arc::new(Doc {
            inner: doc,
            rt: self.async_runtime.clone(),
        }))
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
        let doc = node.create_doc().unwrap();
        let doc_id = doc.id();
        println!("doc_id: {}", doc_id);

        let doc_ticket = doc.share_write().unwrap();
        let doc_ticket_string = doc_ticket.to_string();
        let dock_ticket_back = DocTicket::from_string(doc_ticket_string.clone()).unwrap();
        assert_eq!(doc_ticket.as_ref(), &dock_ticket_back);
        println!("doc_ticket: {}", doc_ticket_string);
        node.import_doc(doc_ticket).unwrap();
    }
}
