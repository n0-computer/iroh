use std::{collections::HashMap, sync::Arc};

use bytes::Bytes;
use cid::Cid;
use tokio::sync::RwLock;

#[async_trait::async_trait]
pub trait Store: 'static + Clone + Send + Sync {
    type Error: std::fmt::Debug + 'static + Send + Sync;

    async fn get(&self, cid: Cid) -> Result<Option<GetResult>, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetResult {
    pub data: Bytes,
    pub links: Vec<(Option<String>, Cid)>,
}

#[async_trait::async_trait]
impl Store for Arc<RwLock<HashMap<Cid, (Bytes, Vec<(String, Cid)>)>>> {
    type Error = ();

    async fn get(&self, cid: Cid) -> Result<Option<GetResult>, Self::Error> {
        if let Some((data, links)) = self.read().await.get(&cid) {
            return Ok(Some(GetResult {
                data: data.clone(),
                links: links
                    .iter()
                    .map(|(name, cid)| (Some(name.clone()), *cid))
                    .collect(),
            }));
        }

        Ok(None)
    }
}

pub type MemoryStore = Arc<RwLock<HashMap<Cid, (Bytes, Vec<(String, Cid)>)>>>;
