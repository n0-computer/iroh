use cid::Cid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, str::FromStr, sync::Arc, time::Duration};
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::log::error;

const BAD_BITS_UPDATE_INTERVAL: Duration = Duration::from_secs(3600 * 8);
const DEFAULT_DENY_LIST_URI: &str = "http://badbits.dwebops.pub/denylist.json";

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BadBitsAnchor {
    pub anchor: String,
}

#[derive(Debug)]
pub struct BadBits {
    pub last_updated: time::Instant,
    pub denylist: HashSet<String>,
}

impl BadBits {
    pub fn new() -> Self {
        Self {
            last_updated: time::Instant::now(),
            denylist: HashSet::new(),
        }
    }

    pub fn update(&mut self, denylist: HashSet<String>) {
        self.last_updated = time::Instant::now();
        self.denylist = denylist;
    }

    pub fn is_bad(&self, cid: &str, path: &str) -> bool {
        let cid = match Cid::from_str(cid) {
            Ok(cid) => cid,
            Err(_) => return false,
        };
        let hash = BadBits::to_anchor(cid, path);
        self.denylist.contains(&hash)
    }

    pub fn to_anchor(cid: Cid, path: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cid.into_v1().unwrap().to_string());
        if !path.is_empty() {
            if path.starts_with('/') {
                hasher.update(path);
            } else {
                hasher.update("/");
                hasher.update(path);
            }
        } else {
            hasher.update("/");
        }
        let x = hasher.finalize().to_vec();
        let mut s = String::new();
        for b in x {
            s.push_str(&format!("{:02x}", b));
        }
        s
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
            let denylist_uri = DEFAULT_DENY_LIST_URI;
            let res = reqwest::get(denylist_uri).await.unwrap();
            if res.status().is_success() {
                let body = res.bytes().await.unwrap();
                if body.len() > 1 << 26 {
                    // 64MB
                    error!("denylist too large");
                } else {
                    let body = serde_json::from_slice::<Vec<BadBitsAnchor>>(&body[..]).unwrap();
                    let new_denylist: HashSet<String> =
                        body.into_iter().map(|anchor| anchor.anchor).collect();
                    bad_bits.write().await.update(new_denylist);
                    println!(
                        "updated denylist: len={}",
                        bad_bits.read().await.denylist.len()
                    );
                }
            } else {
                error!("Failed to fetch denylist: {}", res.status());
            }
            tokio::time::sleep(BAD_BITS_UPDATE_INTERVAL).await;
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
    async fn bad_bits_anchor() {
        let cid =
            Cid::from_str("bafkreidyeivj7adnnac6ljvzj2e3rd5xdw3revw4da7mx2ckrstapoupoq").unwrap();
        let anchor = BadBits::to_anchor(cid, "");
        assert_eq!(
            anchor,
            "d572cfd7fca1f89293f2d71270c51d82445b4502207a0df0707586b3e799521b"
        );

        let cid =
            Cid::from_str("bafkreidyeivj7adnnac6ljvzj2e3rd5xdw3revw4da7mx2ckrstapoupoq").unwrap();
        let path = "/";
        let anchor = BadBits::to_anchor(cid, path);
        assert_eq!(
            anchor,
            "d572cfd7fca1f89293f2d71270c51d82445b4502207a0df0707586b3e799521b"
        );

        let cid =
            Cid::from_str("bafkreidyeivj7adnnac6ljvzj2e3rd5xdw3revw4da7mx2ckrstapoupoq").unwrap();
        let path = "/test";
        let anchor = BadBits::to_anchor(cid, path);
        assert_eq!(
            anchor,
            "b62182173b68ef7ffb1ea5053717b700b80a21a5c28501900b050d704099b3c5"
        );

        let cid = Cid::from_str("QmdZ8zoh1iCsk8TdSAWN49tziH5MMn8XPvJcWmpFD1ygB7").unwrap();
        let path = "";
        let anchor = BadBits::to_anchor(cid, path);
        assert_eq!(
            anchor,
            "1a0e25ca02cd2c97af7e200b9b1a1db11c763473d60c12b8193078c95bbf917f"
        );

        let cid = Cid::from_str("QmdZ8zoh1iCsk8TdSAWN49tziH5MMn8XPvJcWmpFD1ygB7").unwrap();
        let path = "/test";
        let anchor = BadBits::to_anchor(cid, path);
        assert_eq!(
            anchor,
            "bf61fece5f55f922abf36e852b7c329b30350fdcba0d51328c95f33bab0bd5e9"
        );
    }

    #[tokio::test]
    async fn gateway_bad_bits() {
        let bad_cid =
            Cid::from_str("bafkreidyeivj7adnnac6ljvzj2e3rd5xdw3revw4da7mx2ckrstapoupoq").unwrap();
        let bad_path = "bad/foo.jpeg";
        let good_cid =
            Cid::from_str("bafkreieq5jui4j25lacwomsqgjeswwl3y5zcdrresptwgmfylxo2depppq").unwrap();
        let good_path = "good/foo.jpeg";
        let bad_cid_2 =
            Cid::from_str("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi").unwrap();
        let mut bbits = BadBits::new();
        let mut deny_list = HashSet::<String>::new();
        deny_list.insert(BadBits::to_anchor(bad_cid, ""));
        deny_list.insert(BadBits::to_anchor(bad_cid, bad_path));
        deny_list.insert(BadBits::to_anchor(bad_cid_2, bad_path));
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
        assert_eq!(StatusCode::FORBIDDEN, status);

        let uri = hyper::Uri::builder()
            .scheme("http")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query(format!("/ipfs/{}/{}?format=raw", bad_cid_2, bad_path))
            .build()
            .unwrap();
        let client = hyper::Client::new();
        let res = client.get(uri).await.unwrap();
        let status = res.status();
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
