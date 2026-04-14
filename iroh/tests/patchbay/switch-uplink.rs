//! Uplink switch tests.
//!
//! Each test verifies that an iroh connection survives a network change on one
//! side: the switching device replugs from one router to another, and we verify
//! that a new direct path is established and data flows over it.
//!
//! We test every combination of:
//! - which side switches (client or server)
//! - which IP families are involved (v4, v6, dual-stack)
//!
//! The non-switching side is always behind a dual-stack Home NAT, so it is
//! reachable on both address families regardless of what the switcher does.

use std::time::Duration;

use iroh::{TransportAddr, Watcher, endpoint::Side};
use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::{IpSupport, RouterPreset};
use testdir::testdir;
use tracing::info;

use crate::util::{Pair, PathWatcherExt, lab_with_relay, ping_accept, ping_open};

/// Builds the lab topology and runs a single uplink switch test.
///
/// The topology has three routers:
/// - "observer": dual-stack Home NAT for the non-switching side
/// - "from": the switching side's initial router (determined by `from`)
/// - "to": the router the switching side replugs to (determined by `to`)
///
/// After both sides holepunch and exchange a ping, the switching side replugs
/// from "from" to "to". The observer waits for the selected path to change,
/// then both sides exchange another ping to confirm the new path works.
async fn run_switch_uplink(switching_side: Side, from: IpSupport, to: IpSupport) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let timeout = Duration::from_secs(30);

    let observer_id = lab
        .add_router("observer")
        .preset(RouterPreset::Home)
        .ip_support(IpSupport::DualStack)
        .build()
        .await?
        .id();

    let from_id = lab
        .add_router("from")
        .preset(router_preset(from))
        .ip_support(from)
        .build()
        .await?
        .id();
    let to_id = lab
        .add_router("to")
        .preset(router_preset(to))
        .ip_support(to)
        .build()
        .await?
        .id();

    let switcher = lab.add_device("switcher").uplink(from_id).build().await?;
    let observer = lab
        .add_device("observer")
        .uplink(observer_id)
        .build()
        .await?;

    info!(?switching_side, ?from, ?to, "switch uplink test start");

    Pair::new(relay_map)
        .left(switching_side, switcher, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            paths.wait_ip(timeout).await.context("initial holepunch")?;
            ping_accept(&conn, timeout)
                .await
                .context("ping_accept before switch")?;
            dev.iface("eth0").unwrap().replug(to_id).await?;
            ping_accept(&conn, timeout)
                .await
                .context("ping_accept after switch")?;
            conn.closed().await;
            Ok(())
        })
        .right(observer, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            paths.wait_ip(timeout).await.context("initial holepunch")?;
            let previous: Vec<TransportAddr> = paths
                .get()
                .iter()
                .map(|p| p.remote_addr().clone())
                .collect();
            ping_open(&conn, timeout)
                .await
                .context("ping_open before switch")?;
            paths
                .wait_selected(timeout, |p| path_switched(to, &previous, p.remote_addr()))
                .await
                .context("path did not switch")?;
            ping_open(&conn, timeout)
                .await
                .context("ping_open after switch")?;
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;

    guard.ok();
    Ok(())
}

fn router_preset(ip: IpSupport) -> RouterPreset {
    match ip {
        IpSupport::V4Only => RouterPreset::Home,
        IpSupport::V6Only => RouterPreset::IspV6,
        IpSupport::DualStack => RouterPreset::Home,
    }
}

fn path_switched(to: IpSupport, previous: &[TransportAddr], new: &TransportAddr) -> bool {
    if previous.contains(new) {
        return false;
    }
    match to {
        IpSupport::V4Only => matches!(new, TransportAddr::Ip(a) if a.ip().is_ipv4()),
        IpSupport::V6Only => matches!(new, TransportAddr::Ip(a) if a.ip().is_ipv6()),
        IpSupport::DualStack => matches!(new, TransportAddr::Ip(_)),
    }
}

// --- Client switches uplink ---

#[tokio::test]
#[traced_test]
async fn switch_client_v4_to_v4() -> Result {
    run_switch_uplink(Side::Client, IpSupport::V4Only, IpSupport::V4Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_v4_to_v6() -> Result {
    run_switch_uplink(Side::Client, IpSupport::V4Only, IpSupport::V6Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_v4_to_dual() -> Result {
    run_switch_uplink(Side::Client, IpSupport::V4Only, IpSupport::DualStack).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_v6_to_v4() -> Result {
    run_switch_uplink(Side::Client, IpSupport::V6Only, IpSupport::V4Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_v6_to_v6() -> Result {
    run_switch_uplink(Side::Client, IpSupport::V6Only, IpSupport::V6Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_v6_to_dual() -> Result {
    run_switch_uplink(Side::Client, IpSupport::V6Only, IpSupport::DualStack).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_dual_to_v4() -> Result {
    run_switch_uplink(Side::Client, IpSupport::DualStack, IpSupport::V4Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_dual_to_v6() -> Result {
    run_switch_uplink(Side::Client, IpSupport::DualStack, IpSupport::V6Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_dual_to_dual() -> Result {
    run_switch_uplink(Side::Client, IpSupport::DualStack, IpSupport::DualStack).await
}

// --- Server switches uplink ---

#[tokio::test]
#[traced_test]
async fn switch_server_v4_to_v4() -> Result {
    run_switch_uplink(Side::Server, IpSupport::V4Only, IpSupport::V4Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_v4_to_v6() -> Result {
    run_switch_uplink(Side::Server, IpSupport::V4Only, IpSupport::V6Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_v4_to_dual() -> Result {
    run_switch_uplink(Side::Server, IpSupport::V4Only, IpSupport::DualStack).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_v6_to_v4() -> Result {
    run_switch_uplink(Side::Server, IpSupport::V6Only, IpSupport::V4Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_v6_to_v6() -> Result {
    run_switch_uplink(Side::Server, IpSupport::V6Only, IpSupport::V6Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_v6_to_dual() -> Result {
    run_switch_uplink(Side::Server, IpSupport::V6Only, IpSupport::DualStack).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_dual_to_v4() -> Result {
    run_switch_uplink(Side::Server, IpSupport::DualStack, IpSupport::V4Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_dual_to_v6() -> Result {
    run_switch_uplink(Side::Server, IpSupport::DualStack, IpSupport::V6Only).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_dual_to_dual() -> Result {
    run_switch_uplink(Side::Server, IpSupport::DualStack, IpSupport::DualStack).await
}
