use axum::body::StreamBody;
use bytes::Bytes;
use cid::multihash::{Code, MultihashDigest};
use cid::Cid;
use iroh_resolver::resolver::CidOrDomain;
use iroh_resolver::resolver::OutPrettyReader;
use iroh_resolver::resolver::Resolver;
use libipld::codec::Encode;
use libipld::{Ipld, IpldCodec};
use std::sync::Arc;
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
    pub async fn put_raw(
        &self,
        blob: Bytes,
        rpc_client: &iroh_rpc_client::Client,
    ) -> Result<Cid, String> {
        let digest = Code::Blake3_256.digest(&blob);
        let cid = Cid::new_v1(IpldCodec::Raw.into(), digest);
        rpc_client
            .store
            .put(cid, blob, vec![])
            .await
            .map_err(|e| e.to_string())?;
        Ok(cid)
    }

    #[tracing::instrument(skip(rpc_client))]
    pub async fn put_ipld(
        &self,
        input: Ipld,
        rpc_client: &iroh_rpc_client::Client,
    ) -> Result<Cid, String> {
        let codec = IpldCodec::DagCbor;
        let mut blob = Vec::new();
        input.encode(codec, &mut blob).map_err(|e| e.to_string())?;
        let digest = Code::Blake3_256.digest(&blob);
        let cid = Cid::new_v1(codec.into(), digest);
        let mut links = vec![];
        input.references(&mut links);
        rpc_client
            .store
            .put(cid, blob.into(), links)
            .await
            .map_err(|e| e.to_string())?;
        Ok(cid)
    }

    #[tracing::instrument]
    pub async fn get_ipld(
        &self,
        path: &str,
        start_time: std::time::Instant,
        state: Arc<State>,
    ) -> Result<Ipld, String> {
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
        match res.into_ipld() {
            Some(ipld) => Ok(ipld),
            None => Err("This node cannot be represented as IPLD".into()),
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
