//! The reportstate is responsible for generating a single netcheck report.
//!
//! It is implemented as an actor with [`ReportState`] as client or handle.

use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tracing::{debug, error, instrument, warn};

use super::probe::ProbePlan;
use super::Report;

mod hairpin;

/// Holds the state for a single invocation of [`netcheck::Client::get_report`].
///
/// Dropping this will cancel the actor and stop the report generation.
#[derive(Debug, Clone)]
pub(super) struct ReportState {
    actor: Addr,
    _drop_guard: Arc<DropGuard>,
}

impl ReportState {
    fn new(last: Option<Report>, plan: ProbePlan) -> Self {
        todo!()
    }
}

#[derive(Debug)]
struct DropGuard {
    handle: AbortHandle,
}

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.handle.abort()
    }
}

/// The address of the reportstate [`Actor`].
///
/// Unlike the [`ReportState`] struct itself this is the raw channel to send message over.
/// Keeping this alive will not keep the actor alive, which makes this handy to pass to
/// internal tasks.
#[derive(Debug, Clone)]
pub(super) struct Addr {
    sender: mpsc::Sender<Message>,
}

impl Addr {
    /// Blocking send to the actor, to be used from a non-actor future.
    async fn send(&self, msg: Message) -> Result<(), mpsc::error::SendError<Message>> {
        self.sender.send(msg).await.map_err(|err| {
            error!("reportstate actor lost");
            err
        })
    }

    /// Non-blocking send to the actor.
    fn try_send(&self, msg: Message) -> Result<(), mpsc::error::TrySendError<Message>> {
        self.sender.try_send(msg).map_err(|err| {
            match &err {
                mpsc::error::TrySendError::Full(_) => {
                    // TODO: metrics
                    warn!("reportstate actor inbox full");
                }
                mpsc::error::TrySendError::Closed(_) => error!("netcheck actor lost"),
            }
            err
        })
    }
}

/// Messages to send to the reportstate [`Actor`].
#[derive(Debug)]
enum Message {
    /// Set the hairpinning availability in the report.
    HairpinResult(bool),
    Shutdown,
}

/// The reportstate actor.
///
/// This actor runs only for the duration of a generating a single report.
#[derive(Debug)]
struct Actor {
    /// The sender of the message channel, so we can give out [`Addr`].
    msg_tx: mpsc::Sender<Message>,
    /// The receiver of the message channel.
    msg_rx: mpsc::Receiver<Message>,
    /// The address of the netcheck actor.
    netcheck: super::ActorAddr,

    // Internal state.
    /// The report being built.
    report: Report,
    /// Socket to send hairpin STUN checks from, `None` if disabled.
    hair_sock: Option<Arc<UdpSocket>>,
    // hair_tx: stun::TransactionId,
    // got_hair_stun: broadcast::Receiver<SocketAddr>,
    // // notified on hair pin timeout
    // hair_timeout: Arc<sync::Notify>,
    // pc4: Option<Arc<UdpSocket>>,
    // pc6: Option<Arc<UdpSocket>>,
    // /// Doing a lite, follow-up netcheck
    // incremental: bool,
    // stop_probe: Arc<sync::Notify>,
    // wait_port_map: wg::AsyncWaitGroup,
    // sent_hair_check: bool,
    // got_ep4: Option<SocketAddr>,
    // timers: JoinSet<()>,
    // plan: ProbePlan,
    // last: Option<Arc<Report>>,
}

impl Actor {
    async fn new(netcheck: super::ActorAddr) -> Self {
        let (msg_tx, msg_rx) = mpsc::channel(32);
        let hair_sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(sock) => Some(Arc::new(sock)),
            Err(err) => {
                warn!("failed to bind hairpin socket on 0.0.0.0:0: {}", err);
                None
            }
        };
        Actor {
            msg_tx,
            msg_rx,
            netcheck,
            report: Report::default(),
            hair_sock,
        }
    }

    fn addr(&self) -> Addr {
        Addr {
            sender: self.msg_tx.clone(),
        }
    }

    #[instrument(name = "actor", skip_all)]
    async fn run(&mut self) {
        debug!("reportstate actor starting");
        // Prepare hairpin detection infrastructure, needs to be created early.
        let hairpin_actor = hairpin::Client::new(self.netcheck.clone(), self.addr());
    }
}
