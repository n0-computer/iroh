//! NAT traversal matrix tests.
//!
//! Tests holepunching across combinations of the upstream [`patchbay::Nat`]
//! behavior tiers:
//!
//! - `None`: no NAT, publicly routable.
//! - `Open`: endpoint-independent mapping (EIM), endpoint-independent
//!   filtering (EIF); RFC 3489 full cone. Typical of routers with UPnP or
//!   static port forwarding.
//! - `Moderate`: EIM, address-and-port-dependent filtering (APDF); RFC 3489
//!   port-restricted cone. The typical home router.
//! - `Strict`: endpoint-dependent mapping (EDM) with random ports, APDF; RFC
//!   3489 symmetric. Holepunching between two `Strict` NATs requires a relay.
//!
//! Every test expects a direct path to be established. Tests where holepunching
//! is not yet working are marked `#[ignore]`.

use std::time::Duration;

use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::Nat;
use testdir::testdir;
use tracing::info;

use super::util::{Pair, PathConnectionExt, lab_with_relay};
use crate::util::{is_relayed, ping_accept, ping_open};

async fn run_nat_holepunch(nat_server: Nat, nat_client: Nat) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let router_server = lab.add_router("nat_server").nat(nat_server).build().await?;
    let router_client = lab.add_router("nat_client").nat(nat_client).build().await?;
    let server = lab
        .add_device("server")
        .uplink(router_server.id())
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .uplink(router_client.id())
        .build()
        .await?;

    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            conn.wait_ip(timeout).await.context("holepunch to direct")?;
            info!("connection became direct");
            ping_accept(&conn, timeout).await?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            conn.wait_ip(timeout).await.context("holepunch to direct")?;
            info!("connection became direct");
            ping_open(&conn, timeout).await?;
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;

    guard.ok();
    Ok(())
}

// None x *

#[tokio::test]
#[traced_test]
async fn nat_none_x_none() -> Result {
    run_nat_holepunch(Nat::None, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_open() -> Result {
    run_nat_holepunch(Nat::None, Nat::Open).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_moderate() -> Result {
    run_nat_holepunch(Nat::None, Nat::Moderate).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_strict() -> Result {
    run_nat_holepunch(Nat::None, Nat::Strict).await
}

// Open x *

#[tokio::test]
#[traced_test]
async fn nat_open_x_none() -> Result {
    run_nat_holepunch(Nat::Open, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_open_x_open() -> Result {
    run_nat_holepunch(Nat::Open, Nat::Open).await
}

#[tokio::test]
#[traced_test]
async fn nat_open_x_moderate() -> Result {
    run_nat_holepunch(Nat::Open, Nat::Moderate).await
}

#[tokio::test]
#[traced_test]
async fn nat_open_x_strict() -> Result {
    run_nat_holepunch(Nat::Open, Nat::Strict).await
}

// Moderate x *

#[tokio::test]
#[traced_test]
async fn nat_moderate_x_none() -> Result {
    run_nat_holepunch(Nat::Moderate, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_moderate_x_open() -> Result {
    run_nat_holepunch(Nat::Moderate, Nat::Open).await
}

#[tokio::test]
#[traced_test]
async fn nat_moderate_x_moderate() -> Result {
    run_nat_holepunch(Nat::Moderate, Nat::Moderate).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing (and likely can't without port guessing)"]
async fn nat_moderate_x_strict() -> Result {
    run_nat_holepunch(Nat::Moderate, Nat::Strict).await
}

// Strict x *

#[tokio::test]
#[traced_test]
async fn nat_strict_x_none() -> Result {
    run_nat_holepunch(Nat::Strict, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_strict_x_open() -> Result {
    run_nat_holepunch(Nat::Strict, Nat::Open).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing (and likely can't without port guessing)"]
async fn nat_strict_x_moderate() -> Result {
    run_nat_holepunch(Nat::Strict, Nat::Moderate).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing (and likely can't without port guessing)"]
async fn nat_strict_x_strict() -> Result {
    run_nat_holepunch(Nat::Strict, Nat::Strict).await
}

/// Tests for `mapping_varies_by_dest` in net_report.
///
/// A hard NAT (endpoint-dependent mapping) hands out a different external
/// address per destination, so the client's QAD probes to two relays observe
/// two different addresses and net_report must report
/// `mapping_varies_by_dest`. An easy NAT (endpoint-independent mapping) hands
/// out the same address to every destination, so it must not. Two relays are
/// required: mapping-varies can only be decided by comparing the addresses
/// observed against two different destinations.
#[cfg(feature = "unstable-net-report")]
mod mapping_varies {
    use std::time::Duration;

    use iroh::Watcher as _;
    use n0_error::{Result, StackResultExt, StdResultExt};
    use n0_tracing_test::traced_test;
    use patchbay::Nat;
    use testdir::testdir;
    use tracing::info;

    use super::super::util::{endpoint_builder, lab_with_relays};

    /// How long an endpoint may take to come online.
    const ONLINE_TIMEOUT: Duration = Duration::from_secs(10);

    /// Waits until net_report reports `mapping_varies_by_dest() == Some(want)`.
    async fn wait_for_mapping_varies(
        endpoint: &iroh::Endpoint,
        want: bool,
        timeout: Duration,
    ) -> Result {
        tokio::time::timeout(timeout, async {
            let mut watcher = endpoint.net_report();
            loop {
                if watcher.get().and_then(|r| r.mapping_varies_by_dest()) == Some(want) {
                    return Ok::<(), n0_error::AnyError>(());
                }
                watcher.updated().await.anyerr()?;
            }
        })
        .await
        .with_std_context(|_| {
            format!("mapping_varies_by_dest did not reach {want} within {timeout:?}")
        })?
    }

    /// Waits until `endpoint` is online, failing after [`ONLINE_TIMEOUT`].
    async fn wait_online(endpoint: &iroh::Endpoint) -> Result {
        tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online())
            .await
            .std_context("endpoint did not come online")
    }

    /// Asserts the mapping-varies verdict of an endpoint behind `nat`.
    ///
    /// Binds the endpoint and waits until net_report decides
    /// `mapping_varies_by_dest` as `want_varies`.
    async fn run_mapping_varies(nat: Nat, want_varies: bool) -> Result {
        let (lab, relay_map, _relay_guards, guard) = lab_with_relays(testdir!(), 2).await?;
        let router = lab.add_router("nat").nat(nat).build().await?;
        let client = lab.add_device("client").uplink(router.id()).build().await?;

        let timeout = Duration::from_secs(20);
        let task = client.spawn(move |dev| async move {
            let endpoint = endpoint_builder(&dev, relay_map)
                .bind()
                .await
                .context("client endpoint bind")?;
            wait_online(&endpoint).await?;
            info!("endpoint online, waiting for net_report");
            wait_for_mapping_varies(&endpoint, want_varies, timeout).await?;
            Ok::<(), n0_error::AnyError>(())
        })?;
        task.await.anyerr()??;

        guard.ok();
        Ok(())
    }

    /// Asserts that the mapping-varies verdict follows a switch of NAT.
    ///
    /// Binds an endpoint behind a `from` NAT and waits for its verdict. Then
    /// it replugs the device to a `to` NAT and waits for the new verdict.
    ///
    /// This is the case that motivates always waiting for a second QAD
    /// result: after the switch the new cycle must produce a fresh `Some(_)`
    /// verdict, or `ReportHistory::record` would carry the stale value
    /// forward.
    async fn run_mapping_varies_switch(
        from: Nat,
        want_from: bool,
        to: Nat,
        want_to: bool,
    ) -> Result {
        let (lab, relay_map, _relay_guards, guard) = lab_with_relays(testdir!(), 2).await?;
        let from_router = lab.add_router("from").nat(from).build().await?;
        let to_id = lab.add_router("to").nat(to).build().await?.id();
        let client = lab
            .add_device("client")
            .uplink(from_router.id())
            .build()
            .await?;

        let timeout = Duration::from_secs(30);
        let task = client.spawn(move |dev| async move {
            let endpoint = endpoint_builder(&dev, relay_map)
                .bind()
                .await
                .context("client endpoint bind")?;
            wait_online(&endpoint).await?;

            info!(want_from, "waiting for initial mapping-varies verdict");
            wait_for_mapping_varies(&endpoint, want_from, timeout).await?;

            info!("switching networks (replug to the other NAT)");
            dev.iface("eth0").unwrap().replug(to_id).await?;

            info!(want_to, "waiting for mapping-varies to update after switch");
            wait_for_mapping_varies(&endpoint, want_to, timeout).await?;

            Ok::<(), n0_error::AnyError>(())
        })?;
        task.await.anyerr()??;

        guard.ok();
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn hard_nat() -> Result {
        run_mapping_varies(Nat::Strict, true).await
    }

    #[tokio::test]
    #[traced_test]
    async fn easy_nat() -> Result {
        run_mapping_varies(Nat::Moderate, false).await
    }

    #[tokio::test]
    #[traced_test]
    async fn switch_hard_to_easy() -> Result {
        run_mapping_varies_switch(Nat::Strict, true, Nat::Moderate, false).await
    }

    #[tokio::test]
    #[traced_test]
    async fn switch_easy_to_hard() -> Result {
        run_mapping_varies_switch(Nat::Moderate, false, Nat::Strict, true).await
    }
}
