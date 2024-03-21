//! A discovery service which publishes node information to a [Pkarr] relay.
//!
//! This service only implements the [`Discovery::publish`] method and does not provide discovery.
//! It encodes the node information into a DNS packet in the format resolvable by the
//! [`super::dns::DnsDiscovery`], which means a single _iroh_node TXT record, under the z32 encoded
//! node id as origin domain.
//!
//! [pkarr]: https://pkarr.org

// TODO: Decide what to do with this module once publishing over Derpers land. Either remove, or
// leave in the repo but do not enable it by default in the iroh node.

use std::sync::Arc;

use anyhow::Result;
use parking_lot::RwLock;
use pkarr::SignedPacket;
use tracing::warn;
use url::Url;

use crate::{discovery::Discovery, dns::node_info::NodeInfo, key::SecretKey, AddrInfo};

/// The n0 testing pkarr relay
pub const N0_TESTDNS_PKARR_RELAY: &str = "https://testdns.iroh.link/pkarr";

/// Default TTL for the _iroh_node TXT record in the pkarr signed packet
pub const DEFAULT_PKARR_TTL: u32 = 30;

/// Publish node info to a pkarr relay.
#[derive(derive_more::Debug, Clone)]
pub struct Publisher {
    #[debug("SecretKey")]
    secret_key: SecretKey,
    #[debug("PkarrClient")]
    pkarr_client: PkarrRelayClient,
    last_published: Arc<RwLock<Option<NodeInfo>>>,
    ttl: u32,
}

impl Publisher {
    /// Create a new config with a secret key and a pkarr relay URL.
    pub fn new(secret_key: SecretKey, pkarr_relay: Url) -> Self {
        let pkarr_client = PkarrRelayClient::new(pkarr_relay);
        Self {
            secret_key,
            pkarr_client,
            ttl: DEFAULT_PKARR_TTL,
            last_published: Default::default(),
        }
    }

    /// Create a config that publishes to the n0 testdns server.
    pub fn n0_testdns(secret_key: SecretKey) -> Self {
        let pkarr_relay: Url = N0_TESTDNS_PKARR_RELAY.parse().expect("url is valid");
        Self::new(secret_key, pkarr_relay)
    }

    /// Set the TTL for pkarr packets, in seconds.
    ///
    /// Default value is 30 seconds.
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    /// Publish [`AddrInfo`] about this node to a pkarr relay.
    pub async fn publish_addr_info(&self, info: &AddrInfo) -> Result<()> {
        let info = NodeInfo::new(
            self.secret_key.public(),
            info.derp_url.clone().map(Url::from),
            // TODO: optinally support direct addresses
            Default::default(),
        );
        if self.last_published.read().as_ref() == Some(&info) {
            return Ok(());
        }
        let _ = self.last_published.write().insert(info.clone());
        let signed_packet = info.to_pkarr_signed_packet(&self.secret_key, self.ttl)?;
        self.pkarr_client.publish(&signed_packet).await?;
        Ok(())
    }
}

impl Discovery for Publisher {
    fn publish(&self, info: &AddrInfo) {
        let this = self.clone();
        let info = info.clone();
        tokio::task::spawn(async move {
            if let Err(err) = this.publish_addr_info(&info).await {
                warn!("failed to publish address update: {err:?}");
            }
        });
    }
}

/// A pkarr client to publish [`pkarr::SignedPackets`] to a pkarr relay.
#[derive(Debug, Clone)]
pub(crate) struct PkarrRelayClient {
    inner: pkarr::PkarrClient,
    relay_url: Url,
}

impl PkarrRelayClient {
    /// Create a new client.
    pub fn new(relay_url: Url) -> Self {
        Self {
            inner: pkarr::PkarrClient::builder().build(),
            relay_url,
        }
    }

    /// Publish a [`SignedPacket`]
    pub async fn publish(&self, signed_packet: &SignedPacket) -> anyhow::Result<()> {
        self.inner.relay_put(&self.relay_url, signed_packet).await?;
        Ok(())
    }
}
