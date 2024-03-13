//! Actor to run hairpinning check.
//!
//! This actor works as follows:
//!
//! - After starting prepares the haircheck:
//!   - binds socket
//!   - sends traffic from it's socket to trick some routers
//! - When requested performs the hairpin probe.
//!   - result is sent to netcheck actor addr.
//! - Shuts down
//!
//! Note it will only perform a single hairpin check before shutting down.  Any further
//! requests to it will fail which is intentional.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::{debug, error, info_span, trace, warn, Instrument};

use crate::net::UdpSocket;
use crate::netcheck::{self, reportgen, Inflight};
use crate::stun;
use crate::util::CancelOnDrop;

/// The amount of time we wait for a hairpinned packet to come back.
const HAIRPIN_CHECK_TIMEOUT: Duration = Duration::from_millis(100);

/// Handle to the hairpin actor.
///
/// Dropping it will abort the actor.
#[derive(Debug)]
pub(super) struct Client {
    addr: Option<oneshot::Sender<Message>>,
    _drop_guard: CancelOnDrop,
}

impl Client {
    pub(super) fn new(netcheck: netcheck::Addr, reportgen: reportgen::Addr) -> Self {
        let (addr, msg_rx) = oneshot::channel();

        let actor = Actor {
            msg_rx,
            netcheck,
            reportgen,
        };

        let task =
            tokio::spawn(async move { actor.run().await }.instrument(info_span!("hairpin.actor")));
        Self {
            addr: Some(addr),
            _drop_guard: CancelOnDrop::new("hairpin actor", task.abort_handle()),
        }
    }

    /// Returns `true` if we have started a hairpin check before.
    pub(super) fn has_started(&self) -> bool {
        self.addr.is_none()
    }

    /// Starts the hairpin check.
    ///
    /// *dst* should be our own address as discovered by STUN.  Hairpin detection works by
    /// sending a new STUN request to our own public address, if we receive this request
    /// back then hairpinning works, otherwise it does not.
    ///
    /// Will do nothing if this actor is already finished or a check has already started.
    pub(super) fn start_check(&mut self, dst: SocketAddrV4) {
        if let Some(addr) = self.addr.take() {
            addr.send(Message::StartCheck(dst)).ok();
        }
    }
}

#[derive(Debug)]
enum Message {
    /// Performs the hairpin check.
    ///
    /// The STUN request will be sent to the provided [`SocketAddrV4`] which should be our
    /// own address discovered using STUN.
    StartCheck(SocketAddrV4),
}

#[derive(Debug)]
struct Actor {
    msg_rx: oneshot::Receiver<Message>,
    netcheck: netcheck::Addr,
    reportgen: reportgen::Addr,
}

impl Actor {
    async fn run(self) {
        match self.run_inner().await {
            Ok(_) => trace!("hairpin actor finished successfully"),
            Err(err) => error!("Hairpin actor failed: {err:#}"),
        }
    }

    async fn run_inner(self) -> Result<()> {
        let socket = UdpSocket::bind_v4(0).context("Failed to bind hairpin socket on 0.0.0.0:0")?;

        if let Err(err) = Self::prepare_hairpin(&socket).await {
            warn!("unable to send hairpin prep: {err:#}");
            // Continue anyway, most routers are fine.
        }

        // We only have one message to handle
        let Ok(Message::StartCheck(dst)) = self.msg_rx.await else {
            return Ok(());
        };

        let txn = stun::TransactionId::default();
        trace!(%txn, "Sending hairpin with transaction ID");
        let (stun_tx, stun_rx) = oneshot::channel();
        let inflight = Inflight {
            txn,
            start: Instant::now(), // ignored by hairping probe
            s: stun_tx,
        };
        let (msg_response_tx, msg_response_rx) = oneshot::channel();
        self.netcheck
            .send(netcheck::Message::InFlightStun(inflight, msg_response_tx))
            .await
            .context("netcheck actor gone")?;
        msg_response_rx.await.context("netcheck actor died")?;

        if let Err(err) = socket.send_to(&stun::request(txn), dst).await {
            warn!(%dst, "failed to send hairpin check");
            return Err(err.into());
        }

        let now = Instant::now();
        let hairpinning_works = match tokio::time::timeout(HAIRPIN_CHECK_TIMEOUT, stun_rx).await {
            Ok(Ok(_)) => true,
            Ok(Err(_)) => bail!("netcheck actor dropped stun response channel"),
            Err(_) => false, // Elapsed
        };
        debug!(
            "hairpinning done in {:?}, res: {:?}",
            now.elapsed(),
            hairpinning_works
        );

        self.reportgen
            .send(super::Message::HairpinResult(hairpinning_works))
            .await
            .context("Failed to send hairpin result to reportgen actor")?;

        trace!("reportgen notified");

        Ok(())
    }

    async fn prepare_hairpin(socket: &UdpSocket) -> Result<()> {
        // At least the Apple Airport Extreme doesn't allow hairpin
        // sends from a private socket until it's seen traffic from
        // that src IP:port to something else out on the internet.
        //
        // See https://github.com/tailscale/tailscale/issues/188#issuecomment-600728643
        //
        // And it seems that even sending to a likely-filtered RFC 5737
        // documentation-only IPv4 range is enough to set up the mapping.
        // So do that for now. In the future we might want to classify networks
        // that do and don't require this separately. But for now help it.
        let documentation_ip = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 1), 12345));

        socket
            .send_to(
                b"tailscale netcheck; see https://github.com/tailscale/tailscale/issues/188",
                documentation_ip,
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::BytesMut;
    use tokio::sync::mpsc;
    use tracing::info;

    use super::*;

    #[tokio::test]
    async fn test_hairpin_success() {
        for i in 0..100 {
            let now = Instant::now();
            test_hairpin(true).await;
            println!("done round {} in {:?}", i + 1, now.elapsed());
        }
    }

    #[tokio::test]
    async fn test_hairpin_failure() {
        test_hairpin(false).await;
    }

    async fn test_hairpin(hairpinning_works: bool) {
        let _guard = iroh_test::logging::setup();

        // Setup fake netcheck and reportstate actors, hairpinning interacts with them.
        let (netcheck_tx, mut netcheck_rx) = mpsc::channel(32);
        let netcheck_addr = netcheck::Addr {
            sender: netcheck_tx,
        };
        let (reportstate_tx, mut reportstate_rx) = mpsc::channel(32);
        let reportstate_addr = reportgen::Addr {
            sender: reportstate_tx,
        };

        // Create hairpin actor
        let mut actor = Client::new(netcheck_addr, reportstate_addr);

        // Hairpinning works by asking the hairpin actor to send a STUN request to our
        // discovered public address.  If the router returns it hairpinning works.  We
        // emulate this by binding a random socket which we pretend is our publicly
        // discovered address.  The hairpin actor will send it a request and we return it
        // via the inflight channel.
        let public_sock = UdpSocket::bind_local_v4(0).unwrap();
        let ipp_v4 = match public_sock.local_addr().unwrap() {
            SocketAddr::V4(ipp) => ipp,
            SocketAddr::V6(_) => unreachable!(),
        };
        actor.start_check(ipp_v4);

        // This bit is our dummy netcheck actor: it handles the inflight request and sends
        // back the STUN request once it arrives.
        let dummy_netcheck = tokio::spawn(
            async move {
                let netcheck::Message::InFlightStun(inflight, resp_tx) =
                    netcheck_rx.recv().await.unwrap()
                else {
                    panic!("Wrong message received");
                };
                resp_tx.send(()).unwrap();

                let mut buf = BytesMut::zeroed(64 << 10);
                let (count, addr) = public_sock.recv_from(&mut buf).await.unwrap();
                info!(
                    addr=?public_sock.local_addr().unwrap(),
                    %count,
                    "Forwarding payload to hairpin actor",
                );
                let payload = buf.split_to(count).freeze();
                let txn = stun::parse_binding_request(&payload).unwrap();
                assert_eq!(txn, inflight.txn);

                if hairpinning_works {
                    // We want hairpinning to work, send back the STUN request.
                    inflight.s.send((Duration::new(0, 1), addr)).unwrap();
                } else {
                    // We want hairpinning to fail, just wait but do not drop the STUN response
                    // channel because that would make the hairpin actor detect an error.
                    info!("Received hairpin request, not sending response");
                    tokio::time::sleep(HAIRPIN_CHECK_TIMEOUT * 8).await;
                }
            }
            .instrument(info_span!("dummy-netcheck")),
        );

        // Next we expect our dummy reportstate to receive the result.
        match reportstate_rx.recv().await {
            Some(reportgen::Message::HairpinResult(val)) => assert_eq!(val, hairpinning_works),
            Some(msg) => panic!("Unexpected reportstate message: {msg:?}"),
            None => panic!("reportstate mpsc has no senders"),
        }

        // Cleanup: our dummy netcheck actor should finish
        dummy_netcheck.await.expect("error in dummy netcheck actor");
    }

    #[tokio::test]
    async fn test_client_drop() {
        let _guard = iroh_test::logging::setup();

        // Setup fake netcheck and reportstate actors, hairpinning interacts with them.
        let (netcheck_tx, _netcheck_rx) = mpsc::channel(32);
        let netcheck_addr = netcheck::Addr {
            sender: netcheck_tx,
        };
        let (reportstate_tx, _reportstate_rx) = mpsc::channel(32);
        let reportstate_addr = reportgen::Addr {
            sender: reportstate_tx,
        };

        // Create hairpin actor
        let mut client = Client::new(netcheck_addr, reportstate_addr);

        // Save the addr, drop the client
        let addr = client.addr.take();
        drop(client);
        tokio::task::yield_now().await;

        // Check the actor is gone
        let ipp_v4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10);
        match addr.unwrap().send(Message::StartCheck(ipp_v4)) {
            Err(_) => (),
            _ => panic!("actor still running"),
        }
    }
}
