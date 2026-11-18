//! Stream affinity across loss and recovery of a direct path.

use std::time::Duration;

use iroh::{
    TransportAddr,
    endpoint::{Connection, PathId},
};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr};
use n0_future::StreamExt;
use n0_tracing_test::traced_test;
use noq::StreamAffinity;
use patchbay::Firewall;
use testdir::testdir;
use tracing::info;

use super::util::{Pair, lab_with_relay, ping_accept, ping_open};

/// Verifies that stream affinity works end-to-end.
///
/// This test sets up two endpoints connected through two network links, one that
/// reaches the relay server but has UDP blocked, and a shared LAN that only
/// carries direct traffic. It then connects them over the relay link,
/// waits for the connection to become direct, opens a send stream that is sticky
/// to the direct link, brings the direct interface down, and observes that the
/// stream is blocked while only the relay path is available.
#[tokio::test]
#[traced_test]
async fn sticky_direct_survives_outage() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    // eth0 reaches the relay over TCP, but cannot establish direct UDP paths.
    let wan1 = lab
        .add_router("wan1")
        .firewall(Firewall::Corporate)
        .build()
        .await?;
    let wan2 = lab
        .add_router("wan2")
        .firewall(Firewall::Corporate)
        .build()
        .await?;
    // eth1 connects both peers on the same LAN. Only eth0 has a default route,
    // so eth1 carries just the on-link direct path. No firewall here: with
    // br_netfilter loaded, forward rules would also drop the bridged LAN traffic.
    let lan = lab.add_router("lan").build().await?;
    let server = lab
        .add_device("server")
        .iface("eth0", wan1.id())
        .iface("eth1", lan.id())
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .iface("eth0", wan2.id())
        .iface("eth1", lan.id())
        .build()
        .await?;
    let server_lan_ip = server.iface("eth1").unwrap().ip().unwrap();
    let timeout = Duration::from_secs(30);

    let pair = Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
            // Echo each chunk immediately so even a partial leak onto the relay
            // is observable by the client. Replies have unrestricted affinity.
            let echo = async {
                while let Some(chunk) = recv.read_chunk(1024).await.anyerr()? {
                    send.write_chunk(chunk).await.anyerr()?;
                }
                send.finish().anyerr()
            };
            tokio::try_join!(echo, ping_accept(&conn, timeout))?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |dev, _ep, conn| {
            let (direct, addr) = wait_direct(&conn, timeout)
                .await
                .context("initial direct path")?;
            assert!(
                matches!(addr, TransportAddr::Ip(addr) if addr.ip() == server_lan_ip),
                "direct path uses the LAN"
            );
            let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
            send.set_affinity(StreamAffinity::Sticky(direct)).anyerr()?;
            send.write_all(b"before").await.anyerr()?;
            let mut before = [0; 6];
            recv.read_exact(&mut before).await.anyerr()?;
            assert_eq!(&before, b"before");

            info!(%direct, "bringing down the direct LAN interface");
            let direct_iface = dev.iface("eth1").unwrap();
            direct_iface.link_down().await?;
            let mut paths = conn.paths_stream();
            tokio::time::timeout(timeout, async {
                while let Some(paths) = paths.next().await {
                    if !paths.is_empty() && paths.iter().all(|p| p.is_relay()) {
                        return Ok(());
                    }
                }
                Err(anyerr!("path watcher stopped"))
            })
            .await
            .std_context("direct path did not close")??;

            // Keep Sticky unchanged: losing its path must not silently allow
            // this stream's data onto the remaining relay path.
            send.write_all(b"after").await.anyerr()?;
            send.finish().anyerr()?;
            // The connection still carries unrestricted stream data via relay.
            ping_open(&conn, timeout)
                .await
                .context("relay control stream")?;
            let mut byte = [0];
            assert!(
                tokio::time::timeout(Duration::from_secs(2), recv.read(&mut byte))
                    .await
                    .is_err(),
                "pinned stream delivered data or closed while direct was blocked"
            );

            info!("bringing the direct LAN interface back up");
            direct_iface.link_up().await?;
            let (direct, _) = wait_direct(&conn, timeout)
                .await
                .context("restored direct path")?;
            // A closed path's ID need not be reused after recovery.
            send.set_affinity(StreamAffinity::Sticky(direct)).anyerr()?;
            let reply = recv.read_to_end(5).await.anyerr()?;
            assert_eq!(reply, b"after", "queued data survives direct outage");
            conn.close(0u32.into(), b"bye");
            Ok(())
        });
    tokio::time::timeout(Duration::from_secs(90), pair.run())
        .await
        .std_context("stream affinity test timed out")??;
    guard.ok();
    Ok(())
}

/// Waits until a direct path is selected and returns its id and remote address.
async fn wait_direct(conn: &Connection, timeout: Duration) -> Result<(PathId, TransportAddr)> {
    let mut paths = conn.paths_stream();
    tokio::time::timeout(timeout, async {
        while let Some(paths) = paths.next().await {
            if let Some(path) = paths.iter().find(|p| p.is_ip() && p.is_selected()) {
                return Ok((path.id(), path.remote_addr().clone()));
            }
        }
        Err(anyerr!("path watcher stopped"))
    })
    .await
    .std_context("no direct path selected")?
}
