/// A content loader implementation for iroh-one.
use std::collections::HashSet;

use anyhow::Result;
use async_trait::async_trait;
use cid::Cid;
use futures::stream::StreamExt;
use iroh_resolver::resolver::{
    parse_links, ContentLoader, LoadedCid, LoaderContext, Source, IROH_STORE,
};
use iroh_rpc_client::Client as RpcClient;
use tracing::{debug, trace, warn};

#[derive(Clone, Debug)]
pub struct RacingLoader {
    rpc_client: RpcClient,
}

impl RacingLoader {
    pub fn new(rpc_client: RpcClient) -> Self {
        Self { rpc_client }
    }
}

#[async_trait]
impl ContentLoader for RacingLoader {
    async fn load_cid(&self, cid: &Cid, ctx: &LoaderContext) -> Result<LoadedCid> {
        // TODO: better strategy

        let cid = *cid;
        match self.rpc_client.try_store()?.get(cid).await {
            Ok(Some(data)) => {
                trace!("retrieved from store");
                return Ok(LoadedCid {
                    data,
                    source: Source::Store(IROH_STORE),
                });
            }
            Ok(None) => {}
            Err(err) => {
                warn!("failed to fetch data from store {}: {:?}", cid, err);
            }
        }
        let p2p = self.rpc_client.try_p2p()?;
        let mut providers = HashSet::default();
        let mut p = p2p.fetch_providers_dht(&cid).await?;
        while let Some(set) = p.next().await {
            providers.extend(set?);
        }
        let bytes = p2p.fetch_bitswap(ctx.id().into(), cid, providers).await?;

        // trigger storage in the background
        let cloned = bytes.clone();
        let rpc = self.rpc_client.clone();
        tokio::spawn(async move {
            let links = parse_links(&cid, &cloned).unwrap_or_default();

            let len = cloned.len();
            let links_len = links.len();
            if let Some(store_rpc) = rpc.store.as_ref() {
                match store_rpc.put(cid, cloned, links).await {
                    Ok(_) => debug!("stored {} ({}bytes, {}links)", cid, len, links_len),
                    Err(err) => {
                        warn!("failed to store {}: {:?}", cid, err);
                    }
                }
            } else {
                warn!("failed to store: missing store rpc conn");
            }
        });

        trace!("retrieved from p2p");

        Ok(LoadedCid {
            data: bytes,
            source: Source::Bitswap,
        })
    }
}
