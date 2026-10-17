//! NAT64 tests.
//!
//! An IPv6-only client behind a NAT64 carrier (e.g. T-Mobile US) connecting to an IPv4-only
//! server. The two sides share no address family, so a direct path only exists if the client
//! sends to the server's IPv4 addresses through the carrier's NAT64 gateway.

use std::time::Duration;

use iroh::TransportAddr;
use n0_error::{Result, StackResultExt, ensure_any};
use n0_tracing_test::traced_test;
use patchbay::{IpSupport, RouterPreset};
use testdir::testdir;
use tracing::info;

use super::util::{Pair, PathConnectionExt, lab_with_relay};
use crate::util::{ping_accept, ping_open};

async fn run_nat64_to_v4(server_preset: RouterPreset) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let router_server = lab
        .add_router("v4_server")
        .preset(server_preset)
        .ip_support(IpSupport::V4Only)
        .build()
        .await?;
    let router_client = lab
        .add_router("nat64_client")
        .preset(RouterPreset::IspV6)
        .build()
        .await?;
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

    let timeout = Duration::from_secs(30);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            let addr = conn.wait_ip(timeout).await.context("direct path")?;
            info!(%addr, "connection became direct");
            ensure_any!(is_ipv4(&addr), "server path should be IPv4, got {addr}");
            ping_accept(&conn, timeout).await?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, _ep, conn| {
            let addr = conn.wait_ip(timeout).await.context("direct path")?;
            info!(%addr, "connection became direct");
            // The path is to the server's IPv4 address: the NAT64 translation is not visible
            // above the IP transport.
            ensure_any!(is_ipv4(&addr), "client path should be IPv4, got {addr}");
            ping_open(&conn, timeout).await?;
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;

    guard.ok();
    Ok(())
}

fn is_ipv4(addr: &TransportAddr) -> bool {
    matches!(addr, TransportAddr::Ip(a) if a.is_ipv4())
}

/// The server has a public IPv4 address (like a home node with a UPnP port mapping), so the
/// client only needs to send to it through NAT64.
#[tokio::test]
#[traced_test]
async fn nat64_client_x_public_v4_server() -> Result {
    run_nat64_to_v4(RouterPreset::PublicV4).await
}

/// The server is behind a typical home NAT (EIM, APDF), so both sides have to hole punch.
/// The client learns its NAT64 gateway's public address through IPv4 QAD sent over NAT64.
#[tokio::test]
#[traced_test]
async fn nat64_client_x_home_v4_server() -> Result {
    run_nat64_to_v4(RouterPreset::Home).await
}
