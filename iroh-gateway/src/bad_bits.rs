use cid::Cid;
use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, str::FromStr, sync::Arc, time::Duration};
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{debug, log::error};

const BAD_BITS_UPDATE_INTERVAL: Duration = Duration::from_secs(3600 * 8);
const DEFAULT_DENY_LIST_URI: &str = "http://badbits.dwebops.pub/denylist.json";

#[derive(Debug, Deserialize, Serialize, Clone, Eq, Hash, PartialEq)]
pub struct BadBitsAnchor {
    #[serde(rename = "anchor", deserialize_with = "de_from_str")]
    pub value: [u8; 32],
}

fn de_from_str<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let b = hex::decode(&s).unwrap();
    b[..32].try_into().map_err(de::Error::custom)
}

#[derive(Debug)]
pub struct BadBits {
    pub last_updated: time::Instant,
    pub denylist: HashSet<BadBitsAnchor>,
}

impl BadBits {
    pub fn new() -> Self {
        Self {
            last_updated: time::Instant::now(),
            denylist: HashSet::new(),
        }
    }

    pub fn update(&mut self, denylist: HashSet<BadBitsAnchor>) {
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

    pub fn to_anchor(cid: Cid, path: &str) -> BadBitsAnchor {
        let mut hasher = Sha256::new();
        hasher.update(cid.into_v1().unwrap().to_string());
        if !path.starts_with('/') {
            hasher.update("/");
        }
        hasher.update(path);
        BadBitsAnchor {
            value: hasher.finalize()[..].try_into().unwrap(),
        }
    }
}

impl Default for BadBits {
    fn default() -> Self {
        Self::new()
    }
}

pub fn spawn_bad_bits_updater(bad_bits: Arc<Option<RwLock<BadBits>>>) -> Option<JoinHandle<()>> {
    if bad_bits.is_some() {
        return Some(tokio::spawn(async move {
            let bad_bits = bad_bits.as_ref();
            if let Some(bbits) = bad_bits {
                loop {
                    let denylist_uri = DEFAULT_DENY_LIST_URI;
                    let res = reqwest::get(denylist_uri).await.unwrap();
                    if res.status().is_success() {
                        let body = res.bytes().await.unwrap();
                        if body.len() > 1 << 26 {
                            // 64MB
                            error!("denylist too large: {}", body.len());
                        } else {
                            let body =
                                serde_json::from_slice::<Vec<BadBitsAnchor>>(&body[..]).unwrap();
                            let new_denylist = HashSet::from_iter(body);
                            bbits.write().await.update(new_denylist);
                            debug!(
                                "updated denylist: len={}",
                                bbits.read().await.denylist.len()
                            );
                        }
                    } else {
                        error!("Failed to fetch denylist: {}", res.status());
                    }
                    tokio::time::sleep(BAD_BITS_UPDATE_INTERVAL).await;
                }
            }
        }));
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::*;
    use hex_literal::hex;
    use http::StatusCode;
    use iroh_rpc_client::Client as RpcClient;
    use iroh_rpc_client::Config as RpcClientConfig;

    #[tokio::test]
    async fn bad_bits_anchor() {
        let cid =
            Cid::from_str("bafkreidyeivj7adnnac6ljvzj2e3rd5xdw3revw4da7mx2ckrstapoupoq").unwrap();
        let anchor = BadBits::to_anchor(cid, "");
        assert_eq!(
            anchor.value,
            hex!("d572cfd7fca1f89293f2d71270c51d82445b4502207a0df0707586b3e799521b")
        );

        let cid =
            Cid::from_str("bafkreidyeivj7adnnac6ljvzj2e3rd5xdw3revw4da7mx2ckrstapoupoq").unwrap();
        let path = "/";
        let anchor = BadBits::to_anchor(cid, path);
        assert_eq!(
            anchor.value,
            hex!("d572cfd7fca1f89293f2d71270c51d82445b4502207a0df0707586b3e799521b")
        );

        let cid =
            Cid::from_str("bafkreidyeivj7adnnac6ljvzj2e3rd5xdw3revw4da7mx2ckrstapoupoq").unwrap();
        let path = "/test";
        let anchor = BadBits::to_anchor(cid, path);
        assert_eq!(
            anchor.value,
            hex!("b62182173b68ef7ffb1ea5053717b700b80a21a5c28501900b050d704099b3c5")
        );

        let cid = Cid::from_str("QmdZ8zoh1iCsk8TdSAWN49tziH5MMn8XPvJcWmpFD1ygB7").unwrap();
        let path = "";
        let anchor = BadBits::to_anchor(cid, path);
        assert_eq!(
            anchor.value,
            hex!("1a0e25ca02cd2c97af7e200b9b1a1db11c763473d60c12b8193078c95bbf917f")
        );

        let cid = Cid::from_str("QmdZ8zoh1iCsk8TdSAWN49tziH5MMn8XPvJcWmpFD1ygB7").unwrap();
        let path = "/test";
        let anchor = BadBits::to_anchor(cid, path);
        assert_eq!(
            anchor.value,
            hex!("bf61fece5f55f922abf36e852b7c329b30350fdcba0d51328c95f33bab0bd5e9")
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
        let mut deny_list = HashSet::<BadBitsAnchor>::new();
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

        let rpc_addr = "grpc://0.0.0.0:0".parse().unwrap();
        let content_loader = RpcClient::new(config.rpc_client.clone()).await.unwrap();
        let handler = crate::core::Core::new(
            Arc::new(config),
            rpc_addr,
            Arc::new(Some(RwLock::new(bbits))),
            content_loader,
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
            .path_and_query(format!("/ipfs/{}/{}", bad_cid, good_path))
            .build()
            .unwrap();
        let client = hyper::Client::new();
        let res = client.get(uri).await.unwrap();
        assert!(res.status() != StatusCode::FORBIDDEN);

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
