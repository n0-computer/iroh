//! Reproducer for <https://github.com/n0-computer/iroh/issues/4114>:
//! "Invalid retry token when listening on multiple interfaces".
//!
//! ## The bug
//!
//! When a server uses an incoming filter that returns `Retry` (QUIC source
//! address validation) and *both* peers are multi-homed on the same address
//! family, the connection attempt is torn down with `INVALID_TOKEN`:
//!
//! 1. The client dials a direct [`EndpointAddr`] with two server addresses.
//!    With no relay (and therefore no QAD-confirmed preferred address), iroh
//!    has two *unconfirmed* direct candidates and races the first (token-less)
//!    `Initial` across both interfaces. Because the client has two interfaces,
//!    the two `Initial`s leave with two *different* source addresses.
//! 2. The server sees two `Incoming`s and issues a `Retry` for each. Each retry
//!    token is bound to the source address of that path.
//! 3. The client latches onto the *first* retry token (RFC 9000 §17.2.5.2: at
//!    most one Retry is processed) and re-sends a single `Initial` *with that
//!    token*. iroh sends it on both paths.
//! 4. On the path whose source address differs from the one in the token, the
//!    server rejects with `INVALID_TOKEN` and closes — taking the whole
//!    logical connection attempt down with it, even though the other path was
//!    about to complete a valid handshake.
//!
//! This mirrors the real-world setup in the issue (a Pi4 dual-homed over USB-C
//! and WiFi, two IPv4 addresses on separate segments) and the standalone
//! `retry-multi-interface` example that reproduced it: **no relay**, direct
//! dial of a multi-address `EndpointAddr`.
//!
//! ## This test
//!
//! It is a *reproducer*: it asserts the desired behaviour (the connection
//! establishes and a ping round-trips), so on current code it is expected to
//! **fail** — demonstrating the bug. Once the bug is fixed, it should pass as
//! written and become a regression test.
//!
//! Like the rest of the patchbay suite, this only runs on Linux with user
//! namespace support (or under the `patchbay` VM/CLI on other platforms).

use std::{net::SocketAddr, time::Duration};

use iroh::{Endpoint, EndpointAddr, RelayMode, TransportAddr, endpoint::presets};
use n0_error::{Result, StackResultExt, StdResultExt, ensure_any};
use n0_tracing_test::traced_test;
use patchbay::{IfaceConfig, Lab, LinkCondition, LinkDirection, LinkLimits, OutDir, RouterPreset};
use testdir::testdir;
use tokio::sync::oneshot;
use tracing::info;

use crate::util::{TEST_ALPN, ping_accept, ping_open};

/// One-way latency for the "fast" segment (wired-ish).
const SEG_A_LATENCY_MS: u32 = 30;
/// One-way latency for the "slow" segment (wireless-ish).
///
/// The asymmetry is the point: the sprayed first Initial reaches the server over
/// seg_a well before its sibling over seg_b, so seg_a's copy is retried (and its
/// `dst_cid` dedup entry torn down) before seg_b's copy arrives — yielding a
/// *second* incoming and a *second* retry token, bound to seg_b's source. Both
/// segments are slow enough that the handshake takes several RTTs, keeping the
/// initial-spray window open across the retries.
const SEG_B_LATENCY_MS: u32 = 90;

/// A symmetric fixed one-way delay, no loss/jitter (kept deterministic).
fn delay(latency_ms: u32) -> LinkCondition {
    LinkCondition::Manual(LinkLimits {
        latency_ms,
        ..Default::default()
    })
}

/// A pure direct (relay-less) endpoint builder.
fn direct_endpoint() -> iroh::endpoint::Builder {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![TEST_ALPN.to_vec()])
}

/// Two dual-homed peers on two no-NAT segments, no relay; the server validates
/// incoming connections with `Retry`. Reproduces #4114.
#[tokio::test]
#[traced_test]
async fn retry_multi_interface() -> Result {
    // Plain lab, no relay server: the whole point is to keep QAD out of the
    // picture so iroh races the Initial across the direct candidates.
    let mut lab_builder = Lab::builder().outdir(OutDir::Exact(testdir!()));
    if let Some(name) = std::thread::current().name() {
        lab_builder = lab_builder.label(name);
    }
    let lab = lab_builder.build().await?;
    let guard = lab.test_guard();

    // Two directly-routable, no-NAT IPv4 segments (datacenter-style). Devices
    // attached to the same segment share a subnet and reach each other
    // directly, with no translation that would rewrite source addresses.
    let seg_a = lab
        .add_router("seg_a")
        .preset(RouterPreset::PublicV4)
        .build()
        .await?;
    let seg_b = lab
        .add_router("seg_b")
        .preset(RouterPreset::PublicV4)
        .build()
        .await?;

    // Both peers are dual-homed on *both* segments, so each can reach the other
    // on two distinct same-family addresses. The kernel picks the source
    // interface per destination subnet, giving two different source addresses —
    // the precondition for the token mismatch.
    //
    // Asymmetric latency on the server's two interfaces: seg_a fast, seg_b slow.
    // The sprayed first Initial reaches the server over seg_a well before its
    // sibling over seg_b, so seg_a's copy is retried (and its `dst_cid` dedup
    // entry torn down) before seg_b's copy arrives — producing a *second*
    // incoming and a *second* retry token bound to seg_b's source. Both links
    // are slow enough that the handshake spans several RTTs, keeping the
    // initial-spray window open across the retries.
    let server = lab
        .add_device("server")
        .iface(
            "eth0",
            IfaceConfig::routed(seg_a.id()).condition(delay(SEG_A_LATENCY_MS), LinkDirection::Both),
        )
        .iface(
            "eth1",
            IfaceConfig::routed(seg_b.id()).condition(delay(SEG_B_LATENCY_MS), LinkDirection::Both),
        )
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .iface("eth0", IfaceConfig::routed(seg_a.id()))
        .iface("eth1", IfaceConfig::routed(seg_b.id()))
        .build()
        .await?;

    let timeout = Duration::from_secs(15);
    let (addr_tx, addr_rx) = oneshot::channel();

    let server_task = server.spawn::<_, _, Result<()>>(move |dev| async move {
        let endpoint = direct_endpoint().bind().await.context("server bind")?;
        info!(
            id = %endpoint.id().fmt_short(),
            bound_sockets = ?endpoint.bound_sockets(),
            "server endpoint bound",
        );

        // Build a direct, IP-only address by hand from the two interface IPs and
        // the bound UDP port. No relay, no address lookup, no `online()` — just
        // the two same-family addresses, exactly like the example in the issue.
        let port = endpoint
            .bound_sockets()
            .into_iter()
            .find(|s| s.is_ipv4())
            .context("no bound IPv4 socket")?
            .port();
        let ip_a = dev.iface("eth0").context("eth0")?.ip().context("eth0 ip")?;
        let ip_b = dev.iface("eth1").context("eth1")?.ip().context("eth1 ip")?;
        let direct = EndpointAddr::from_parts(
            endpoint.id(),
            [
                TransportAddr::Ip(SocketAddr::new(ip_a.into(), port)),
                TransportAddr::Ip(SocketAddr::new(ip_b.into(), port)),
            ],
        );
        info!(?direct, "server direct address (IP-only, two interfaces)");
        addr_tx.send(direct).unwrap();

        // Retry-then-validate accept loop: send a `Retry` for every unvalidated
        // incoming, accept once the source address has been validated. This is
        // the same filter shape as the `addr_retry_then_validated` unit test in
        // `protocol.rs`, which works fine when single-homed.
        let conn = loop {
            let incoming = endpoint.accept().await.context("server accept")?;
            if incoming.remote_addr_validated() {
                info!(remote = ?incoming.remote_addr(), "incoming validated, accepting");
                break incoming
                    .accept()
                    .anyerr()?
                    .await
                    .context("server accept handshake")?;
            }
            info!(remote = ?incoming.remote_addr(), "unvalidated incoming, sending retry");
            // Ignore the error: `retry()` only fails if already validated, which
            // the branch above already handles.
            let _ = incoming.retry();
        };
        info!(remote = %conn.remote_id().fmt_short(), "accepted, echoing one ping");
        ping_accept(&conn, timeout).await.context("ping_accept")?;
        conn.closed().await;
        Ok(())
    })?;

    let client_task = client.spawn::<_, _, Result<()>>(move |_dev| async move {
        let endpoint = direct_endpoint().bind().await.context("client bind")?;
        info!(
            id = %endpoint.id().fmt_short(),
            bound_sockets = ?endpoint.bound_sockets(),
            "client endpoint bound",
        );
        let addr = addr_rx
            .await
            .std_context("server did not send its address")?;
        info!(?addr, "connecting (direct, multi-address, no relay)");
        let conn = endpoint
            .connect(addr, TEST_ALPN)
            .await
            .context("client connect")?;
        info!(remote = %conn.remote_id().fmt_short(), "connected, sending one ping");
        ping_open(&conn, timeout).await.context("ping_open")?;
        conn.close(0u32.into(), b"bye");
        Ok(())
    })?;

    let (server_res, client_res) = tokio::join!(server_task, client_task);
    server_res
        .std_context("server task panicked")?
        .context("server task failed")?;
    client_res
        .std_context("client task panicked")?
        .context("client task failed")?;

    guard.ok();
    Ok(())
}

/// Pure-UDP diagnostic (no iroh): does the dual-homed topology actually give the
/// client a *different source address* per server address?
///
/// This is the precondition for #4114: the retry-token mismatch can only happen
/// if Initials to the two server addresses leave the client from two different
/// source interfaces. The iroh reproducer ([`retry_multi_interface`]) saw only a
/// single source on the server, so before blaming iroh we check whether patchbay
/// routes the two destinations out of two interfaces at all.
///
/// It checks two things:
/// 1. **Client-side route selection**: `connect()` a UDP socket to each server
///    address and read back `local_addr()` — the kernel's chosen source.
/// 2. **What the server actually receives**: the client sends a datagram to each
///    server address; the server records the observed source addresses.
///
/// The test asserts both pairs of sources are distinct, and dumps the client's
/// routing table / addresses for context.
#[tokio::test]
#[traced_test]
async fn topology_distinct_source_per_server_addr() -> Result {
    let mut lab_builder = Lab::builder().outdir(OutDir::Exact(testdir!()));
    if let Some(name) = std::thread::current().name() {
        lab_builder = lab_builder.label(name);
    }
    let lab = lab_builder.build().await?;
    let guard = lab.test_guard();

    let seg_a = lab
        .add_router("seg_a")
        .preset(RouterPreset::PublicV4)
        .build()
        .await?;
    let seg_b = lab
        .add_router("seg_b")
        .preset(RouterPreset::PublicV4)
        .build()
        .await?;

    let server = lab
        .add_device("server")
        .iface("eth0", IfaceConfig::routed(seg_a.id()))
        .iface("eth1", IfaceConfig::routed(seg_b.id()))
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .iface("eth0", IfaceConfig::routed(seg_a.id()))
        .iface("eth1", IfaceConfig::routed(seg_b.id()))
        .build()
        .await?;

    // server -> client: (addr_a, addr_b) to probe.
    let (addr_tx, addr_rx) = oneshot::channel();
    // client -> server: hand-off so the server knows when both datagrams are sent.
    let (done_tx, done_rx) = oneshot::channel::<()>();

    let server_task = server.spawn::<_, _, Result<()>>(move |dev| async move {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .std_context("server bind")?;
        let port = sock.local_addr().std_context("server local_addr")?.port();
        let ip_a = dev.iface("eth0").context("eth0")?.ip().context("eth0 ip")?;
        let ip_b = dev.iface("eth1").context("eth1")?.ip().context("eth1 ip")?;
        let addr_a = SocketAddr::new(ip_a.into(), port);
        let addr_b = SocketAddr::new(ip_b.into(), port);
        info!(%addr_a, %addr_b, "server listening on both interfaces");
        addr_tx.send((addr_a, addr_b)).unwrap();

        // Receive the two probe datagrams and record the source addresses.
        let mut buf = [0u8; 16];
        let recv_two = async {
            let (_, src1) = sock.recv_from(&mut buf).await.std_context("recv 1")?;
            let (_, src2) = sock.recv_from(&mut buf).await.std_context("recv 2")?;
            Result::<(SocketAddr, SocketAddr)>::Ok((src1, src2))
        };
        let (src1, src2) = tokio::time::timeout(Duration::from_secs(5), recv_two)
            .await
            .std_context("timed out waiting for probe datagrams")??;
        info!(%src1, %src2, "server received probes from these sources");
        ensure_any!(
            src1.ip() != src2.ip(),
            "server saw the SAME source IP for both addresses ({} == {}): \
             the two segments are not forcing distinct egress interfaces",
            src1.ip(),
            src2.ip(),
        );

        done_rx.await.std_context("client did not finish")?;
        Ok(())
    })?;

    let client_task = client.spawn::<_, _, Result<()>>(move |_dev| async move {
        let (addr_a, addr_b) = addr_rx.await.std_context("server addrs")?;

        // Context: dump the client's IPv4 routes and addresses.
        for (label, args) in [("routes", ["-4", "route"]), ("addrs", ["-4", "addr"])] {
            if let Ok(out) = std::process::Command::new("ip").args(args).output() {
                info!(%label, "{}", String::from_utf8_lossy(&out.stdout).trim());
            }
        }

        // (1) Client-side route lookup: which source does the kernel pick per dest?
        let src_for = |dest: SocketAddr| -> Result<SocketAddr> {
            let s = std::net::UdpSocket::bind("0.0.0.0:0").std_context("probe bind")?;
            s.connect(dest).std_context("probe connect")?;
            Ok(s.local_addr().std_context("probe local_addr")?)
        };
        let src_a = src_for(addr_a)?;
        let src_b = src_for(addr_b)?;
        info!(%addr_a, %src_a, %addr_b, %src_b, "client route-selected source per server address");

        // (2) Actually send a datagram to each, so the server can confirm.
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .std_context("client send bind")?;
        sock.send_to(b"a", addr_a).await.std_context("send a")?;
        sock.send_to(b"b", addr_b).await.std_context("send b")?;
        done_tx.send(()).ok();

        ensure_any!(
            src_a.ip() != src_b.ip(),
            "client route lookup picked the SAME source IP for both server \
             addresses ({} == {}): the topology does not provide two egress \
             interfaces",
            src_a.ip(),
            src_b.ip(),
        );
        Ok(())
    })?;

    let (server_res, client_res) = tokio::join!(server_task, client_task);
    server_res
        .std_context("server task panicked")?
        .context("server task failed")?;
    client_res
        .std_context("client task panicked")?
        .context("client task failed")?;

    guard.ok();
    Ok(())
}
