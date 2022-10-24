use crate::resolver::{
    parse_links, ContentLoader, ContextId, LoadedCid, LoaderContext, Source, IROH_STORE,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::{multibase, Cid};
use futures::{future::FutureExt, pin_mut, select};
use iroh_rpc_client::Client as RpcClient;
use rand::seq::SliceRandom;
use tracing::{debug, error, trace, warn};

#[derive(Clone, Debug)]
pub struct RacingLoader {
    rpc_client: RpcClient,
    http_resolvers: Vec<String>,
}

impl RacingLoader {
    pub fn new(rpc_client: RpcClient, http_resolvers: Vec<String>) -> Self {
        Self {
            rpc_client,
            http_resolvers,
        }
    }
}

impl RacingLoader {
    pub fn try_raw_gateway(&self) -> Result<&String> {
        match self.http_resolvers.len() {
            0 => Err(anyhow!("no gateway configured to fetch raw CIDs")),
            _ => {
                let mut rng = rand::thread_rng();
                let gw = self.http_resolvers.choose(&mut rng).unwrap();
                Ok(gw)
            }
        }
    }

    async fn fetch_p2p(&self, ctx: ContextId, cid: &Cid) -> Result<Bytes, anyhow::Error> {
        let p2p = self.rpc_client.try_p2p()?;
        p2p.fetch_bitswap(ctx.into(), *cid, Default::default())
            .await
    }

    async fn fetch_http(&self, cid: &Cid) -> Result<(Bytes, String), anyhow::Error> {
        let gateway = self.try_raw_gateway()?;
        let cid_str = multibase::encode(multibase::Base::Base32Lower, cid.to_bytes().as_slice());
        // support two gateway URL formats: subdomain gateways (eg: dweb.link)
        // and full URL (eg: https://ipfs.io)
        let gateway_url = if gateway.starts_with("https://") || gateway.starts_with("http://") {
            format!("{}/ipfs/{}?format=raw", gateway, cid_str)
        } else {
            format!("https://{}.ipfs.{}?format=raw", cid_str, gateway)
        };
        debug!("Will fetch {}", gateway_url);
        let response = reqwest::get(gateway_url).await?;
        response
            .bytes()
            .await
            .map(|bytes| (bytes, gateway.clone()))
            .map_err(|e| e.into())
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

        let p2p_fut = self.fetch_p2p(ctx.id(), &cid).fuse();
        let http_fut = self.fetch_http(&cid).fuse();
        pin_mut!(p2p_fut, http_fut);

        let mut bytes: Option<Bytes> = None;
        let mut source = Source::Bitswap;

        // Race the p2p and http fetches.
        loop {
            select! {
                res = http_fut => {
                    if let Ok((data, url)) = res {
                        debug!("retrieved from http");
                        if let Some(true) = iroh_util::verify_hash(&cid, &data) {
                            source = Source::Http(url);
                            bytes = Some(data);
                            break;
                        } else {
                            error!("Got http data, but CID verification failed!");
                        }
                    }
                }
                res = p2p_fut => {
                    if let Ok(data) = res {
                        debug!("retrieved from p2p");
                        bytes = Some(data);
                        break;
                    }
                }
                complete => { break; }
            }
        }

        if let Some(bytes) = bytes {
            // trigger storage in the background
            let cloned = bytes.clone();
            let rpc = self.rpc_client.clone();
            tokio::spawn(async move {
                let links = parse_links(&cid, &cloned).unwrap_or_default();

                let len = cloned.len();
                let links_len = links.len();
                if let Ok(store_rpc) = rpc.try_store() {
                    match store_rpc.clone().put(cid, cloned, links).await {
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
                source,
            })
        } else {
            Err(anyhow::anyhow!("Failed to load from p2p & http"))
        }
    }

    async fn stop_session(&self, ctx: ContextId) -> Result<()> {
        self.rpc_client
            .try_p2p()?
            .stop_session_bitswap(ctx.into())
            .await?;
        Ok(())
    }

    async fn has_cid(&self, cid: &Cid) -> Result<bool> {
        Ok(self.rpc_client.try_store()?.has(*cid).await?)
    }
}
