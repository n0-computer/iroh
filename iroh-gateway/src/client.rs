use std::sync::Arc;

use axum::body::StreamBody;
use iroh_resolver::resolver::CidOrDomain;
use iroh_resolver::resolver::OutPrettyReader;
use iroh_resolver::resolver::Resolver;
use tokio_util::io::ReaderStream;
use tracing::info;

use crate::core::State;
use crate::response::ResponseFormat;

#[derive(Debug)]
pub struct Client {
    resolver: Resolver<iroh_rpc_client::Client>,
}

pub type PrettyStreamBody = StreamBody<ReaderStream<OutPrettyReader<iroh_rpc_client::Client>>>;

impl Client {
    pub fn new(rpc_client: &iroh_rpc_client::Client) -> Self {
        Self {
            resolver: Resolver::new(rpc_client.clone()),
        }
    }

    #[tracing::instrument(skip(rpc_client))]
    pub async fn get_file(
        &self,
        path: &str,
        rpc_client: &iroh_rpc_client::Client,
        start_time: std::time::Instant,
        state: Arc<State>,
    ) -> Result<PrettyStreamBody, String> {
        info!("get file {}", path);
        state.metrics.cache_miss.inc();
        let p: iroh_resolver::resolver::Path =
            path.parse().map_err(|e: anyhow::Error| e.to_string())?;
        // todo(arqu): this is wrong but currently don't have access to the data stream
        state
            .metrics
            .ttf_block
            .set(start_time.elapsed().as_millis() as u64);
        state
            .metrics
            .hist_ttfb
            .observe(start_time.elapsed().as_millis() as f64);
        let res = self.resolver.resolve(p).await.map_err(|e| e.to_string())?;
        let reader = res.pretty(rpc_client.clone());
        let stream = ReaderStream::new(reader);
        let body = StreamBody::new(stream);

        Ok(body)
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub format: ResponseFormat,
    pub cid: CidOrDomain,
    pub full_content_path: String,
    pub query_file_name: String,
    pub content_path: String,
    pub download: bool,
}
