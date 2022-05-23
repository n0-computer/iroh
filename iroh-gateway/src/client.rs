use std::sync::Arc;

use axum::body::Body;
use cid::Cid;
use tracing::{error, info};

use crate::core::State;
use crate::response::ResponseFormat;

#[derive(Debug, Clone, Copy)]
pub struct Client {}

impl Client {
    pub fn new() -> Self {
        Self {}
    }

    #[tracing::instrument(skip(rpc_client))]
    pub async fn get_file(
        &self,
        path: &str,
        rpc_client: &iroh_rpc_client::Client,
        start_time: std::time::Instant,
        state: Arc<State>,
    ) -> Result<Body, String> {
        info!("get file {}", path);
        state.metrics.cache_miss.inc();
        let p: iroh_resolver::resolver::Path =
            path.parse().map_err(|e: anyhow::Error| e.to_string())?;
        // TODO: reuse
        let resolver = iroh_resolver::resolver::Resolver::new(rpc_client.clone());
        let path = path.to_string();

        // todo(arqu): this is wrong but currently don't have access to the data stream
        state
            .metrics
            .ttf_block
            .set(start_time.elapsed().as_millis() as u64);
        state
            .metrics
            .hist_ttfb
            .observe(start_time.elapsed().as_millis() as f64);
        let res = resolver
            .resolve(p)
            .await
            .and_then(|r| r.pretty())
            .map_err(|e| e.to_string())?;
        info!("resolved: {}", path);
        state
            .metrics
            .tts_file
            .set(start_time.elapsed().as_millis() as u64);
        let n = res.len() as u64;
        state
            .metrics
            .bytes_per_sec_out
            .set(n / start_time.elapsed().as_secs());
        state.metrics.bytes_streamed.inc_by(n);
        Ok(res.into())
    }

    #[tracing::instrument()]
    pub async fn get_file_by_cid(
        &self,
        c: Cid,
        rpc_client: &iroh_rpc_client::Client,
        start_time: std::time::Instant,
    ) -> Result<Body, String> {
        info!("get file {}", c);
        let (mut sender, body) = Body::channel();
        let rpc_client = rpc_client.clone();
        tokio::spawn(async move {
            // fetch some providers
            // TODO
            // let providers = match rpc_client.network.fetch_provider(c.to_bytes().into()).await {
            //     Ok(providers) => Some(providers),
            //     Err(e) => {
            //         error!("failed to fetch providers {:?}", e);
            //         None
            //     }
            // };
            let providers = None;

            match rpc_client.p2p.fetch_bitswap(c, providers).await {
                Ok(res) => {
                    if let Err(e) = sender.send_data(res).await {
                        error!("failed to send data: {:?}", e);
                    }
                }
                Err(e) => {
                    error!("{:?}", e);
                    sender.abort();
                }
            }
        });

        Ok(body)
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub format: ResponseFormat,
    pub cid: Cid,
    pub full_content_path: String,
    pub query_file_name: String,
    pub content_path: String,
    pub download: bool,
}
