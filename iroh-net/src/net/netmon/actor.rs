use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use futures::future::BoxFuture;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, trace, warn};

#[cfg(target_os = "android")]
use super::android as os;
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
use super::bsd as os;
#[cfg(target_os = "linux")]
use super::linux as os;
#[cfg(target_os = "windows")]
use super::windows as os;

use os::{is_interesting_interface, RouteMonitor};

use crate::net::{
    interfaces::{IpNet, State},
    ip::is_link_local,
};

/// The message sent by the OS specific monitors.
#[derive(Debug, Copy, Clone)]
pub(super) enum NetworkMessage {
    /// A change was detected.
    #[allow(dead_code)]
    Change,
}

/// How often we execute a check for big jumps in wall time.
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const POLL_WALL_TIME_INTERVAL: Duration = Duration::from_secs(15);
/// Set background polling time to 1h to effectively disable it on mobile,
/// to avoid increased battery usage. Sleep detection won't work this way there.
#[cfg(any(target_os = "ios", target_os = "android"))]
const POLL_WALL_TIME_INTERVAL: Duration = Duration::from_secs(60 * 60);
const MON_CHAN_CAPACITY: usize = 16;
const ACTOR_CHAN_CAPACITY: usize = 16;

pub(super) struct Actor {
    /// Latest known interface state.
    interface_state: State,
    /// Latest observed wall time.
    wall_time: Instant,
    /// OS specific monitor.
    #[allow(dead_code)]
    route_monitor: RouteMonitor,
    mon_receiver: flume::Receiver<NetworkMessage>,
    actor_receiver: mpsc::Receiver<ActorMessage>,
    actor_sender: mpsc::Sender<ActorMessage>,
    /// Callback registry.
    callbacks: HashMap<CallbackToken, Arc<Callback>>,
    callback_token: u64,
}

/// Token to remove a callback
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CallbackToken(u64);

/// Callbacks that get notified about changes.
pub(super) type Callback = Box<dyn Fn(bool) -> BoxFuture<'static, ()> + Sync + Send + 'static>;

pub(super) enum ActorMessage {
    Subscribe(Callback, oneshot::Sender<CallbackToken>),
    Unsubscribe(CallbackToken, oneshot::Sender<()>),
}

impl Actor {
    pub(super) async fn new() -> Result<Self> {
        let interface_state = State::new().await;
        let wall_time = Instant::now();

        // Use flume channels, as tokio::mpsc is not safe to use across ffi boundaries.
        let (mon_sender, mon_receiver) = flume::bounded(MON_CHAN_CAPACITY);
        let route_monitor = RouteMonitor::new(mon_sender)?;
        let (actor_sender, actor_receiver) = mpsc::channel(ACTOR_CHAN_CAPACITY);

        Ok(Actor {
            interface_state,
            wall_time,
            route_monitor,
            mon_receiver,
            actor_receiver,
            actor_sender,
            callbacks: Default::default(),
            callback_token: 0,
        })
    }

    pub(super) fn subscribe(&self) -> mpsc::Sender<ActorMessage> {
        self.actor_sender.clone()
    }

    pub(super) async fn run(mut self) {
        const DEBOUNCE: Duration = Duration::from_millis(250);

        let mut last_event = None;
        let mut debounce_interval = tokio::time::interval(DEBOUNCE);
        let mut wall_time_interval = tokio::time::interval(POLL_WALL_TIME_INTERVAL);

        loop {
            tokio::select! {
                biased;
                _ = debounce_interval.tick() => {
                    if let Some(time_jumped) = last_event.take() {
                        if let Err(err) = self.handle_potential_change(time_jumped).await {
                            warn!("failed to handle network changes: {:?}", err);
                        };
                    }
                }
                _ = wall_time_interval.tick() => {
                    trace!("tick: wall_time_interval");
                    if self.check_wall_time_advance() {
                        // Trigger potential change
                        last_event.replace(true);
                        debounce_interval.reset_immediately();
                    }
                }
                Ok(_event) = self.mon_receiver.recv_async() => {
                    trace!("network activity detected");
                    last_event.replace(false);
                    debounce_interval.reset_immediately();
                }
                Some(msg) = self.actor_receiver.recv() => match msg {
                    ActorMessage::Subscribe(callback, s) => {
                        let token = self.next_callback_token();
                        self.callbacks.insert(token, Arc::new(callback));
                        s.send(token).ok();
                    }
                    ActorMessage::Unsubscribe(token, s) => {
                        self.callbacks.remove(&token);
                        s.send(()).ok();
                    }
                },
                else => {
                    break;
                }
            }
        }
    }

    fn next_callback_token(&mut self) -> CallbackToken {
        let token = CallbackToken(self.callback_token);
        self.callback_token += 1;
        token
    }

    async fn handle_potential_change(&mut self, time_jumped: bool) -> Result<()> {
        info!("potential change");

        let new_state = State::new().await;
        let old_state = &self.interface_state;

        // No major changes, continue on
        if !time_jumped && old_state == &new_state {
            debug!("no changes detected");
            return Ok(());
        }

        let is_major = is_major_change(old_state, &new_state) || time_jumped;

        if is_major {
            self.interface_state = new_state;
        }

        debug!("triggering {} callbacks", self.callbacks.len());
        for cb in self.callbacks.values() {
            let cb = cb.clone();
            tokio::task::spawn(async move {
                cb(is_major).await;
            });
        }

        Ok(())
    }

    /// Reports whether wall time jumped more than 150%
    /// of `POLL_WALL_TIME_INTERVAL`, indicating we probably just came out of sleep.
    fn check_wall_time_advance(&mut self) -> bool {
        let now = Instant::now();
        let jumped = if let Some(elapsed) = now.checked_duration_since(self.wall_time) {
            elapsed > POLL_WALL_TIME_INTERVAL * 3 / 2
        } else {
            false
        };

        self.wall_time = now;
        jumped
    }
}

fn is_major_change(s1: &State, s2: &State) -> bool {
    if s1.have_v6 != s2.have_v6
        || s1.have_v4 != s2.have_v4
        || s1.is_expensive != s2.is_expensive
        || s1.default_route_interface != s2.default_route_interface
        || s1.http_proxy != s2.http_proxy
        || s1.pac != s2.pac
    {
        return true;
    }

    for (iname, i) in &s1.interfaces {
        if !is_interesting_interface(i.name()) {
            continue;
        }
        let Some(i2) = s2.interfaces.get(iname) else {
            return true;
        };
        if i != i2 || !prefixes_major_equal(i.addrs(), i2.addrs()) {
            return true;
        }
    }

    false
}

/// Checks wheter `a` and `b` are equal after ignoring uninteresting
/// things, like link-local, loopback and multicast addresses.
fn prefixes_major_equal(a: impl Iterator<Item = IpNet>, b: impl Iterator<Item = IpNet>) -> bool {
    fn is_interesting(p: &IpNet) -> bool {
        let a = p.addr();
        if is_link_local(a) || a.is_loopback() || a.is_multicast() {
            return false;
        }
        true
    }

    let a = a.filter(is_interesting);
    let b = b.filter(is_interesting);

    for (a, b) in a.zip(b) {
        if a != b {
            return false;
        }
    }

    true
}
