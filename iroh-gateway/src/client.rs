use std::sync::Arc;

use axum::body::StreamBody;
use iroh_resolver::resolver::CidOrDomain;
use iroh_resolver::resolver::Metadata;
use iroh_resolver::resolver::OutPrettyReader;
use iroh_resolver::resolver::Resolver;
use tokio_util::io::ReaderStream;
use tracing::info;

use crate::core::GetParams;
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
        path: iroh_resolver::resolver::Path,
        rpc_client: &iroh_rpc_client::Client,
        start_time: std::time::Instant,
        state: Arc<State>,
    ) -> Result<(PrettyStreamBody, Metadata), String> {
        info!("get file {}", path);
        state.metrics.cache_miss.inc();
        // todo(arqu): this is wrong but currently don't have access to the data stream
        state
            .metrics
            .ttf_block
            .set(start_time.elapsed().as_millis() as u64);
        state
            .metrics
            .hist_ttfb
            .observe(start_time.elapsed().as_millis() as f64);
        let res = self
            .resolver
            .resolve(path)
            .await
            .map_err(|e| e.to_string())?;
        let metadata = res.metadata().clone();
        let reader = res.pretty(rpc_client.clone());
        let stream = ReaderStream::new(reader);
        let body = StreamBody::new(stream);

        Ok((body, metadata))
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub format: ResponseFormat,
    pub cid: CidOrDomain,
    pub resolved_path: iroh_resolver::resolver::Path,
    pub query_file_name: String,
    pub content_path: String,
    pub download: bool,
    pub query_params: GetParams,
}
