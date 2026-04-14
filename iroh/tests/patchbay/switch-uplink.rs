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

use iroh::{TransportAddr, endpoint::Side};
use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::{IpSupport, RouterPreset};
use testdir::testdir;
use tracing::info;

use crate::util::{Pair, PathWatcherExt, lab_with_relay, ping_accept, ping_open};

fn router_preset(ip: IpSupport) -> RouterPreset {
    match ip {
        IpSupport::V4Only => RouterPreset::Home,
        IpSupport::V6Only => RouterPreset::IspV6,
        IpSupport::DualStack => RouterPreset::Home,
    }
}

fn path_switched(to: IpSupport, first: &TransportAddr, new: &TransportAddr) -> bool {
    if new == first {
        return false;
    }
    match to {
        IpSupport::V4Only => matches!(new, TransportAddr::Ip(a) if a.ip().is_ipv4()),
        IpSupport::V6Only => matches!(new, TransportAddr::Ip(a) if a.ip().is_ipv6()),
        IpSupport::DualStack => matches!(new, TransportAddr::Ip(_)),
    }
}

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

    let (server_uplink, client_uplink) = match switching_side {
        Side::Client => (observer_id, from_id),
        Side::Server => (from_id, observer_id),
    };
    let server = lab
        .add_device("server")
        .uplink(server_uplink)
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .uplink(client_uplink)
        .build()
        .await?;

    info!(?switching_side, ?from, ?to, "switch uplink test start");

    /// The switching side: holepunches, pings, replugs to a new router, pings again.
    ///
    /// Waits for the peer to close the connection after the second ping succeeds.
    async fn do_switch(
        dev: patchbay::Device,
        conn: iroh::endpoint::Connection,
        timeout: Duration,
        to_id: patchbay::NodeId,
    ) -> Result {
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
    }

    /// The observing side: holepunches, pings, waits for the path to change, pings again.
    ///
    /// After the switching side replugs, the observer sees the selected path change
    /// to match the expected address family (or a new address for same-family switches).
    /// Closes the connection after the second ping succeeds.
    async fn do_observe(
        conn: iroh::endpoint::Connection,
        timeout: Duration,
        to: IpSupport,
    ) -> Result {
        let mut paths = conn.paths();
        let first = paths.wait_ip(timeout).await.context("initial holepunch")?;
        ping_open(&conn, timeout)
            .await
            .context("ping_open before switch")?;
        paths
            .wait_selected(timeout, |p| {
                path_switched(to, first.remote_addr(), p.remote_addr())
            })
            .await
            .context("path did not switch")?;
        ping_open(&conn, timeout)
            .await
            .context("ping_open after switch")?;
        conn.close(0u32.into(), b"bye");
        Ok(())
    }

    let pair = Pair::new(relay_map);
    let pair = match switching_side {
        Side::Client => pair
            .server(server, async move |_dev, _ep, conn| {
                do_observe(conn, timeout, to).await
            })
            .client(client, async move |dev, _ep, conn| {
                do_switch(dev, conn, timeout, to_id).await
            }),
        Side::Server => pair
            .server(server, async move |dev, _ep, conn| {
                do_switch(dev, conn, timeout, to_id).await
            })
            .client(client, async move |_dev, _ep, conn| {
                do_observe(conn, timeout, to).await
            }),
    };
    pair.run().await?;

    guard.ok();
    Ok(())
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
