//! Home relay tests.
//!
//! The net report picks the home relay from the relays' latencies. When the
//! home relay becomes unreachable, the endpoint must move to another relay.

use std::time::Duration;

use iroh::{RelayUrl, Watcher as _};
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_tracing_test::traced_test;
use patchbay::Nat;
use testdir::testdir;
use tracing::info;

use crate::util::{endpoint_builder, lab_with_relays};

/// How long the endpoint may take to come online.
const ONLINE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the endpoint may take to move to another relay after an outage.
///
/// The relay transport pings its home relay every 15 seconds. A missing pong
/// ends the connection, and when the redial fails the net report moves on at
/// once. The QUIC idle timeout of the kept QAD connections (35 seconds) and
/// the periodic refresh play no part.
const SWITCH_TIMEOUT: Duration = Duration::from_secs(25);

/// How long the offline test keeps the client offline.
const OFFLINE: Duration = Duration::from_secs(20);

/// Returns the device name of the relay at `url` in [`lab_with_relays`].
fn relay_device(url: &RelayUrl) -> String {
    let host = url.host_str().expect("relay url has a host");
    host.strip_suffix(".test")
        .expect("lab relay host")
        .to_string()
}

/// Cuts the link of the home relay and checks that the endpoint moves on.
#[tokio::test]
#[traced_test]
async fn home_relay_outage() -> Result {
    let (lab, relay_map, _relay_guards, guard) = lab_with_relays(testdir!(), 3).await?;
    let nat = lab.add_router("nat").nat(Nat::Moderate).build().await?;
    let client = lab.add_device("client").uplink(nat.id()).build().await?;

    let (home_tx, home_rx) = tokio::sync::oneshot::channel();
    let (outage_tx, outage_rx) = tokio::sync::oneshot::channel::<()>();
    let task = client.spawn(move |dev| async move {
        let endpoint = endpoint_builder(&dev, relay_map)
            .bind()
            .await
            .context("client endpoint bind")?;
        tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online())
            .await
            .std_context("endpoint did not come online")?;
        let home = endpoint.home_relay_status().get()[0].url().clone();
        info!(%home, "online");
        home_tx.send(home.clone()).ok();
        outage_rx.await.anyerr()?;

        let start = tokio::time::Instant::now();
        let mut status = endpoint.home_relay_status();
        let new_home = tokio::time::timeout(SWITCH_TIMEOUT, async {
            loop {
                if let Some(s) = status.get().first()
                    && s.url() != &home
                    && s.is_connected()
                {
                    return s.url().clone();
                }
                status.updated().await.expect("endpoint alive");
            }
        })
        .await
        .std_context("endpoint did not move to another relay")?;
        info!(%new_home, elapsed = ?start.elapsed(), "moved to another relay");
        Ok::<_, n0_error::AnyError>(start.elapsed())
    })?;

    let home = home_rx.await.anyerr()?;
    // Let the kept QAD connections age, so that a close can trigger a refresh.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let relay = lab
        .device_by_name(&relay_device(&home))
        .expect("home relay device");
    info!(%home, "cutting the link of the home relay");
    relay
        .iface("eth0")
        .expect("relay iface")
        .link_down()
        .await?;
    outage_tx.send(()).ok();

    let elapsed = task.await.anyerr()??;
    info!(?elapsed, "endpoint moved to another relay");
    guard.ok();
    Ok(())
}

/// Takes the client offline and checks that the home relay does not rotate.
///
/// Offline, no relay can be dialed. The endpoint may move away from its home
/// relay once, but must not keep moving between relays it cannot reach. Back
/// online, it must reconnect to a relay.
#[tokio::test]
#[traced_test]
async fn home_relay_offline() -> Result {
    let (lab, relay_map, _relay_guards, guard) = lab_with_relays(testdir!(), 3).await?;
    let nat = lab.add_router("nat").nat(Nat::Moderate).build().await?;
    let client = lab.add_device("client").uplink(nat.id()).build().await?;

    let task = client.spawn(move |dev| async move {
        let endpoint = endpoint_builder(&dev, relay_map)
            .bind()
            .await
            .context("client endpoint bind")?;
        tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online())
            .await
            .std_context("endpoint did not come online")?;
        tokio::time::sleep(Duration::from_secs(6)).await;

        info!("taking the client offline");
        let iface = dev.iface("eth0").expect("client iface");
        iface.link_down().await?;
        let mut status = endpoint.home_relay_status();
        let mut home = status.get().first().map(|s| s.url().clone());
        let mut moves = 0;
        let offline = tokio::time::sleep(OFFLINE);
        tokio::pin!(offline);
        loop {
            tokio::select! {
                _ = &mut offline => break,
                res = status.updated() => {
                    let url = res.anyerr()?.first().map(|s| s.url().clone());
                    if url != home {
                        info!(?url, "home relay moved while offline");
                        home = url;
                        moves += 1;
                    }
                }
            }
        }
        n0_error::ensure_any!(moves <= 1, "home relay moved {moves} times while offline");

        info!("bringing the client back online");
        iface.link_up().await?;
        tokio::time::timeout(SWITCH_TIMEOUT * 2, async {
            loop {
                if status.get().first().is_some_and(|s| s.is_connected()) {
                    return;
                }
                status.updated().await.expect("endpoint alive");
            }
        })
        .await
        .std_context("endpoint did not reconnect to a relay")?;
        Ok::<_, n0_error::AnyError>(())
    })?;
    task.await.anyerr()??;
    guard.ok();
    Ok(())
}
