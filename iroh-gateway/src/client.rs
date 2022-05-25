use std::sync::Arc;

use axum::body::Body;
use cid::Cid;
use tracing::info;

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
        let res = resolver.resolve(p).await.map_err(|e| e.to_string())?;
        let res = res.pretty(rpc_client).await.map_err(|e| e.to_string())?;

        info!("resolved: {}", path);
        state
            .metrics
            .tts_file
            .set(start_time.elapsed().as_millis() as u64);
        let n = res.len() as u64;
        state
            .metrics
            .bytes_per_sec_out
            .set(n / start_time.elapsed().as_secs().max(1));
        state.metrics.bytes_streamed.inc_by(n);
        Ok(res.into())
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
