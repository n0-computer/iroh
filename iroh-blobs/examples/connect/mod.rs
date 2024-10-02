//! Common code used to created connections in the examples

use anyhow::{Context, Result};
use futures_lite::StreamExt;
use iroh_net::discovery::dns::DnsDiscovery;
use iroh_net::discovery::local_swarm_discovery::LocalSwarmDiscovery;
use iroh_net::discovery::pkarr::PkarrPublisher;
use iroh_net::discovery::ConcurrentDiscovery;
use iroh_net::key::SecretKey;

pub const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/bytes/0";

pub async fn make_iroh_endpoint() -> Result<iroh_net::Endpoint> {
    let secret_key = SecretKey::generate();
    let discovery = ConcurrentDiscovery::from_services(vec![
        Box::new(PkarrPublisher::n0_dns(secret_key.clone())),
        Box::new(DnsDiscovery::n0_dns()),
        Box::new(LocalSwarmDiscovery::new(secret_key.public())?),
    ]);
    let ep = iroh_net::Endpoint::builder()
        .secret_key(secret_key)
        .discovery(Box::new(discovery))
        .alpns(vec![EXAMPLE_ALPN.to_vec()])
        .bind()
        .await?;
    // Wait for full connectivity
    ep.direct_addresses()
        .next()
        .await
        .context("no direct addrs")?;
    Ok(ep)
}
