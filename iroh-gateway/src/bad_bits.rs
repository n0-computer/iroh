use crypto::{digest::Digest, sha2::Sha256};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::log::error;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BadBitsAnchor {
    pub anchor: String,
}

#[derive(Debug)]
pub struct BadBits {
    pub last_updated: time::Instant,
    pub denylist: HashMap<String, bool>,
}

impl BadBits {
    pub fn new() -> Self {
        Self {
            last_updated: time::Instant::now(),
            denylist: HashMap::new(),
        }
    }

    pub fn update(&mut self, denylist: HashMap<String, bool>) {
        self.last_updated = time::Instant::now();
        self.denylist = denylist;
    }

    pub fn is_bad(&self, cid: &str, path: &str) -> bool {
        let hash = BadBits::to_anchor(cid, path);
        *self.denylist.get(&hash).unwrap_or(&false)
    }

    pub fn to_anchor(cid: &str, path: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.input_str(cid);
        if !path.is_empty() {
            if path.starts_with('/') {
                hasher.input_str(path);
            } else {
                hasher.input_str("/");
                hasher.input_str(path);
            }
        }
        hasher.result_str()
    }
}

impl Default for BadBits {
    fn default() -> Self {
        Self::new()
    }
}

pub fn bad_bits_update_handler(bad_bits: Arc<RwLock<BadBits>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let denylist_uri = "http://badbits.dwebops.pub/denylist.json";
            let res = reqwest::get(denylist_uri).await.unwrap();
            if res.status().is_success() {
                let body = res.bytes().await.unwrap();
                let body = serde_json::from_slice::<Vec<BadBitsAnchor>>(&body[..]).unwrap();
                let new_denylist: HashMap<String, bool> = body
                    .into_iter()
                    .map(|anchor| (anchor.anchor, true))
                    .collect();
                bad_bits.write().await.update(new_denylist);
                println!(
                    "updated denylist: len={}",
                    bad_bits.read().await.denylist.len()
                );
            } else {
                error!("Failed to fetch denylist: {}", res.status());
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::*;
    use http::StatusCode;
    use iroh_metrics::gateway::Metrics;
    use iroh_rpc_client::Config as RpcClientConfig;
    use prometheus_client::registry::Registry;

    #[tokio::test]
    async fn gateway_bad_bits() {
        let bad_cid = "bafkreidyeivj7adnnac6ljvzj2e3rd5xdw3revw4da7mx2ckrstapoupoq";
        let bad_path = "bad/foo.jpeg";
        let good_cid = "bafkreieq5jui4j25lacwomsqgjeswwl3y5zcdrresptwgmfylxo2depppq";
        let good_path = "good/foo.jpeg";
        let bad_cid_2 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let mut bbits = BadBits::new();
        let mut deny_list = HashMap::<String, bool>::new();
        deny_list.insert(BadBits::to_anchor(bad_cid, ""), true);
        deny_list.insert(BadBits::to_anchor(bad_cid, bad_path), true);
        deny_list.insert(BadBits::to_anchor(bad_cid_2, bad_path), true);
        bbits.update(deny_list);

        let mut config = Config::new(
            false,
            false,
            false,
            0,
            RpcClientConfig {
                gateway_addr: None,
                p2p_addr: None,
                store_addr: None,
            },
        );
        config.set_default_headers();

        let mut prom_registry = Registry::default();
        let gw_metrics = Metrics::new(&mut prom_registry);
        let rpc_addr = "grpc://0.0.0.0:0".parse().unwrap();
        let handler = crate::core::Core::new(
            config,
            rpc_addr,
            gw_metrics,
            &mut prom_registry,
            Arc::new(RwLock::new(bbits)),
        )
        .await
        .unwrap();
        let server = handler.server();
        let addr = server.local_addr();
        let core_task = tokio::spawn(async move {
            server.await.unwrap();
        });

        let uri = hyper::Uri::builder()
            .scheme("http")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query(format!("/ipfs/{}", bad_cid))
            .build()
            .unwrap();
        let client = hyper::Client::new();
        let res = client.get(uri).await.unwrap();
        assert_eq!(StatusCode::FORBIDDEN, res.status());

        let uri = hyper::Uri::builder()
            .scheme("http")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query(format!("/ipfs/{}/{}", bad_cid, bad_path))
            .build()
            .unwrap();
        let client = hyper::Client::new();
        let res = client.get(uri).await.unwrap();
        assert_eq!(StatusCode::FORBIDDEN, res.status());

        let uri = hyper::Uri::builder()
            .scheme("http")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query(format!("/ipfs/{}/{}", bad_cid, good_path))
            .build()
            .unwrap();
        let client = hyper::Client::new();
        let res = client.get(uri).await.unwrap();
        assert_eq!(StatusCode::FORBIDDEN, res.status());

        let uri = hyper::Uri::builder()
            .scheme("http")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query(format!("/ipfs/{}/{}", bad_cid_2, bad_path))
            .build()
            .unwrap();
        let client = hyper::Client::new();
        let res = client.get(uri).await.unwrap();
        let status = res.status();
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        let r = String::from_utf8(body.to_vec()).unwrap();
        println!("{}", r);
        assert_eq!(StatusCode::FORBIDDEN, status);

        let uri = hyper::Uri::builder()
            .scheme("http")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query(format!("/ipfs/{}/{}", bad_cid_2, good_path))
            .build()
            .unwrap();
        let client = hyper::Client::new();
        let res = client.get(uri).await.unwrap();
        assert!(res.status() != StatusCode::FORBIDDEN);

        let uri = hyper::Uri::builder()
            .scheme("http")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query(format!("/ipfs/{}", good_cid))
            .build()
            .unwrap();
        let client = hyper::Client::new();
        let res = client.get(uri).await.unwrap();
        assert!(res.status() != StatusCode::FORBIDDEN);

        core_task.abort();
        core_task.await.unwrap_err();
    }
}
