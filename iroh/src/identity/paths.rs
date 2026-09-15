//! Identity-independent QUIC NAT traversal over the authenticated connection.

use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};

use n0_future::StreamExt;
use noq::Runtime as _;

use super::routing::Routing;
use crate::runtime::Runtime;

/// Resolve a relay's QAD target, handling IP literal hosts without DNS.
async fn resolve(url: &crate::RelayUrl, port: u16) -> Option<(Vec<SocketAddr>, String)> {
    match url.host()? {
        url::Host::Ipv4(ip) => Some((vec![SocketAddr::new(ip.into(), port)], ip.to_string())),
        url::Host::Ipv6(ip) => Some((vec![SocketAddr::new(ip.into(), port)], ip.to_string())),
        url::Host::Domain(host) => {
            let addresses = tokio::net::lookup_host((host, port)).await.ok()?;
            Some((addresses.collect(), host.to_owned()))
        }
    }
}

/// Periodically observe this endpoint's public addresses through relay QAD.
///
/// `base` holds the interface and configured addresses enumerated at bind.
/// Each round publishes `base` plus the currently observed addresses, so a
/// failed probe only withdraws mappings that QAD itself contributed.
pub(super) fn discover(
    runtime: &Arc<Runtime>,
    endpoint: noq::Endpoint,
    tls: Arc<rustls::ClientConfig>,
    targets: Vec<(crate::RelayUrl, u16)>,
    base: BTreeSet<SocketAddr>,
    candidates: tokio::sync::watch::Sender<BTreeSet<SocketAddr>>,
) {
    runtime.spawn(Box::pin(async move {
        let client = iroh_relay::quic::QuicClient::new(endpoint, (*tls).clone());
        loop {
            let mut current = BTreeSet::new();
            for (url, port) in &targets {
                let result = tokio::time::timeout(Duration::from_secs(3), async {
                    let (addresses, host) = resolve(url, *port)
                        .await
                        .ok_or_else(|| std::io::Error::other("relay host did not resolve"))?;
                    for address in addresses {
                        let address = match address {
                            SocketAddr::V4(v4) => {
                                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
                            }
                            v6 => v6,
                        };
                        let Ok(connection) = client.create_conn(address, &host).await else {
                            continue;
                        };
                        // Closing on cancellation also releases the QAD connection.
                        struct Close(noq::Connection);
                        impl Drop for Close {
                            fn drop(&mut self) {
                                self.0.close(0u32.into(), b"address observed");
                            }
                        }
                        let close = Close(connection);
                        let mut reports = close.0.observed_external_addr();
                        if let Some(address) = reports.next().await {
                            return Ok::<_, std::io::Error>(SocketAddr::new(
                                address.ip().to_canonical(),
                                address.port(),
                            ));
                        }
                    }
                    Err(std::io::Error::other("no observed address"))
                })
                .await;
                if let Ok(Ok(address)) = result {
                    current.insert(address);
                }
            }
            candidates.send_if_modified(|values| {
                let mut next = base.clone();
                next.extend(current.iter().copied());
                if *values == next {
                    false
                } else {
                    *values = next;
                    true
                }
            });
            tokio::time::sleep(Duration::from_secs(25)).await;
        }
    }));
}

/// Drive NAT traversal for one authenticated connection.
///
/// The task holds only a weak handle. Once the application drops its last
/// [`super::Connection`], the QUIC connection closes implicitly and the
/// task ends; a strong clone here would keep both alive indefinitely.
pub(super) fn start(
    runtime: &Arc<Runtime>,
    connection: noq::Connection,
    routing: Routing,
    mut candidates: tokio::sync::watch::Receiver<BTreeSet<SocketAddr>>,
    lease: super::routing::RouteLease,
) -> tokio::sync::watch::Receiver<bool> {
    let initial_direct = connection
        .path(noq::PathId::ZERO)
        .and_then(|path| path.network_path().ok())
        .is_some_and(|path| routing.relay_for(path.remote()).is_none());
    let (direct_tx, direct_rx) = tokio::sync::watch::channel(initial_direct);
    let mut events = connection.path_events();
    let mut updates = connection.nat_traversal_updates();
    let handle = connection.weak_handle();
    drop(connection);
    runtime.spawn(Box::pin(async move {
        let _lease = lease;
        let mut direct = BTreeSet::new();
        let mut relayed = BTreeSet::new();
        if initial_direct { direct.insert(noq::PathId::ZERO); } else { relayed.insert(noq::PathId::ZERO); }
        let mut retry = tokio::time::interval(Duration::from_secs(5));
        loop {
            {
                let Some(connection) = handle.upgrade() else { break };
                if connection.close_reason().is_some() { break; }
                let local = candidates.borrow_and_update().clone();
                if let Ok(current) = connection.get_local_nat_traversal_addresses() {
                    let current: BTreeSet<_> = current.into_iter().map(|a| SocketAddr::new(a.ip().to_canonical(), a.port())).collect();
                    for address in local.difference(&current) { let _ = connection.add_nat_traversal_address(*address); }
                    for address in current.difference(&local) { let _ = connection.remove_nat_traversal_address(*address); }
                }
                if direct.is_empty() && connection.side().is_client() { let _ = connection.initiate_nat_traversal_round(); }
            }
            // No strong handle is held across these awaits.
            tokio::select! {
                result = candidates.changed() => { if result.is_err() { break; } }
                _ = retry.tick() => {}
                update = updates.next() => { if update.is_none() { break; } }
                event = events.next() => {
                    let Some(connection) = handle.upgrade() else { break };
                    match event {
                        Some(Ok(noq::PathEvent::Established { id, .. })) => {
                            if let Some(path) = connection.path(id)
                                && let Ok(network) = path.network_path() {
                                    if routing.relay_for(network.remote()).is_none() {
                                        direct.insert(id);
                                        let _ = path.set_status(noq::PathStatus::Available);
                                    } else { relayed.insert(id); }
                            }
                        }
                        Some(Ok(noq::PathEvent::Abandoned { id, .. } | noq::PathEvent::Discarded { id, .. })) => { direct.remove(&id); relayed.remove(&id); }
                        None => break,
                        _ => {}
                    }
                    for id in &relayed {
                        if let Some(path) = connection.path(*id) {
                            let _ = path.set_status(if direct.is_empty() { noq::PathStatus::Available } else { noq::PathStatus::Backup });
                        }
                    }
                    direct_tx.send_replace(!direct.is_empty());
                }
            }
        }
    }));
    direct_rx
}
