use pkarr::SignedPacket;
use tracing::warn;
use url::Url;

#[derive(Debug, Clone)]
pub struct PkarrClient {
    inner: pkarr::PkarrClient,
    relay_url: Url,
}

impl PkarrClient {
    pub fn new(relay_url: Url) -> Self {
        Self {
            inner: pkarr::PkarrClient::builder().build(),
            relay_url,
        }
    }

    pub fn publish(&self, signed_packet: SignedPacket) {
        let c = self.clone();
        tokio::task::spawn(async move {
            if let Err(err) = c.inner.relay_put(&c.relay_url, &signed_packet).await {
                warn!(?err, url = %c.relay_url, "failed to publish to pkarr")
            }
        });
    }
}
