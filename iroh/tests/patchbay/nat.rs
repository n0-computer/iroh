//! NAT traversal matrix tests.
//!
//! Tests holepunching across combinations of NAT types (None, Home, Corporate).
//!
//! - None: no NAT, publicly routable
//! - Home: endpoint-independent mapping (EIM), address-and-port-dependent
//!   filtering (APDF), port-preserving (typical home router)
//! - Corporate: endpoint-dependent mapping (EDM), APDF, random ports per
//!   destination (enterprise firewall, cloud NAT)
//!
//! Every test expects a direct path to be established. Tests where holepunching
//! is not yet working are marked `#[ignore]`.

use std::time::Duration;

use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::Nat;
use testdir::testdir;
use tracing::info;

use crate::util::{ping_accept, ping_open};

use super::util::{Pair, PathWatcherExt, lab_with_relay};

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
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            paths
                .wait_ip(timeout)
                .await
                .context("holepunch to direct")?;
            info!("connection became direct");
            ping_accept(&conn, timeout).await?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            paths
                .wait_ip(timeout)
                .await
                .context("holepunch to direct")?;
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

#[tokio::test]
#[traced_test]
async fn nat_none_x_none() -> Result {
    run_nat_holepunch(Nat::None, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_home() -> Result {
    run_nat_holepunch(Nat::None, Nat::Home).await
}

#[tokio::test]
#[traced_test]
async fn nat_home_x_none() -> Result {
    run_nat_holepunch(Nat::Home, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_corporate() -> Result {
    run_nat_holepunch(Nat::None, Nat::Corporate).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn nat_corporate_x_none() -> Result {
    run_nat_holepunch(Nat::Corporate, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_home_x_home() -> Result {
    run_nat_holepunch(Nat::Home, Nat::Home).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn nat_home_x_corporate() -> Result {
    run_nat_holepunch(Nat::Home, Nat::Corporate).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn nat_corporate_x_home() -> Result {
    run_nat_holepunch(Nat::Corporate, Nat::Home).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn nat_corporate_x_corporate() -> Result {
    run_nat_holepunch(Nat::Corporate, Nat::Corporate).await
}
