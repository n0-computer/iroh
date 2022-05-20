use std::sync::Arc;
use std::{fs::File, io::Read, path::Path, time::Duration};

use axum::body::Body;
use cid::Cid;
use rand::{prelude::StdRng, Rng, SeedableRng};
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

    #[tracing::instrument()]
    pub async fn get_file_simulated(
        &self,
        _path: &str,
        start_time: std::time::Instant,
        state: Arc<State>,
    ) -> Result<Body, String> {
        let (mut sender, body) = Body::channel();
        let mut rng: StdRng = SeedableRng::from_entropy();

        // some random latency
        tokio::time::sleep(Duration::from_millis(rng.gen_range(0..650))).await;

        tokio::spawn(async move {
            let test_path = Path::new("test_files/test_big.txt");
            let mut file = File::open(test_path).unwrap();
            let mut buf = [0u8; 1024];
            let mut first_block = true;
            if rng.gen_range(0..250) < 200 {
                // simulate a cache miss
                state.metrics.cache_miss.inc();
            } else {
                // simulate a cache hit
                state.metrics.cache_hit.inc();
            }

            let mut f_size: u64 = 0;

            while let Ok(n) = file.read(&mut buf) {
                if first_block {
                    state
                        .metrics
                        .ttf_block
                        .set(start_time.elapsed().as_millis() as u64);
                    state
                        .metrics
                        .hist_ttfb
                        .observe(start_time.elapsed().as_millis() as f64);
                }
                state.metrics.bytes_fetched.inc_by(n as u64);
                f_size += n as u64;
                state
                    .metrics
                    .bitrate_in
                    .set(f_size / start_time.elapsed().as_secs());
                if n == 0 {
                    state
                        .metrics
                        .ttf_file
                        .set(start_time.elapsed().as_millis() as u64);
                    state
                        .metrics
                        .tts_file
                        .set(start_time.elapsed().as_millis() as u64);
                    state
                        .metrics
                        .hist_ttsf
                        .observe(start_time.elapsed().as_millis() as f64);
                    break;
                }
                sender
                    .send_data(axum::body::Bytes::from(buf[..n].to_vec()))
                    .await
                    .unwrap();
                // todo(arqu): handle sender error
                if first_block {
                    first_block = false;
                    state
                        .metrics
                        .tts_block
                        .set(start_time.elapsed().as_millis() as u64);
                }
                state
                    .metrics
                    .bitrate_out
                    .set(f_size / start_time.elapsed().as_secs());
                state.metrics.bytes_streamed.inc_by(n as u64);
                tokio::time::sleep(Duration::from_millis(rng.gen_range(0..250))).await;
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
