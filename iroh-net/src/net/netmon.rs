//! Monitoring of networking interfaces and route changes.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::net::{interfaces::State, ip::is_link_local};
use anyhow::Result;
use futures::future::BoxFuture;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, info, trace, warn};

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
mod bsd;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
use bsd as os;
#[cfg(any(target_os = "linux", target_os = "android"))]
use linux as os;
#[cfg(target_os = "windows")]
use windows as os;

use os::{is_interesting_interface, RouteMonitor};

use super::interfaces::IpNet;

/// Monitors networking interface and route changes.
#[derive(Debug)]
pub struct Monitor {
    /// Task handle for the monitor task.
    handle: JoinHandle<()>,
    actor_tx: mpsc::Sender<ActorMessage>,
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// How often we execute a check for big jumps in wall time.
const POLL_WALL_TIME_INTERVAL: Duration = Duration::from_secs(15);

impl Monitor {
    /// Create a new monitor.
    pub async fn new() -> Result<Self> {
        let actor = Actor::new().await?;
        let actor_tx = actor.subscribe();

        let handle = tokio::task::spawn(async move {
            actor.run().await;
        });

        Ok(Monitor { handle, actor_tx })
    }

    /// Subscribe to network changes.
    pub async fn subscribe<F>(&self, callback: F) -> Result<CallbackToken>
    where
        F: Fn(bool) -> BoxFuture<'static, ()> + 'static + Sync + Send,
    {
        let (s, r) = oneshot::channel();
        self.actor_tx
            .send(ActorMessage::Subscribe(Box::new(callback), s))
            .await?;
        let token = r.await?;
        Ok(token)
    }

    /// Unsubscribe a callback from network changes, using the provided token.
    pub async fn unsubscribe(&self, token: CallbackToken) -> Result<()> {
        let (s, r) = oneshot::channel();
        self.actor_tx
            .send(ActorMessage::Unsubscribe(token, s))
            .await?;
        let res = r.await?;
        Ok(res)
    }
}

struct Actor {
    /// Latest known interface state.
    interface_state: State,
    /// Latest observed wall time.
    wall_time: Instant,
    /// OS specific monitor.
    #[allow(dead_code)]
    route_monitor: RouteMonitor,
    handle: JoinHandle<()>,
    actor_rx: mpsc::Receiver<ActorMessage>,
    actor_tx: mpsc::Sender<ActorMessage>,
    callbacks: HashMap<CallbackToken, Arc<Callback>>,
    callback_token: u64,
}

impl Drop for Actor {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Token to remove a callback
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CallbackToken(u64);

/// Callbacks that get notified about changes.
pub type Callback = Box<dyn Fn(bool) -> BoxFuture<'static, ()> + Sync + Send + 'static>;

enum ActorMessage {
    NetworkActivity,
    Subscribe(Callback, oneshot::Sender<CallbackToken>),
    Unsubscribe(CallbackToken, oneshot::Sender<()>),
}

impl Actor {
    async fn new() -> Result<Self> {
        let interface_state = State::new().await;
        let wall_time = Instant::now();

        let (s, mut r) = mpsc::channel(16);
        let route_monitor = RouteMonitor::new(s).await?;
        let (actor_tx, actor_rx) = mpsc::channel(16);

        let sender = actor_tx.clone();
        let handle = tokio::task::spawn(async move {
            while let Some(_msg) = r.recv().await {
                sender
                    .send(ActorMessage::NetworkActivity)
                    .await
                    .expect("actor task died");
            }
        });

        Ok(Actor {
            interface_state,
            wall_time,
            route_monitor,
            handle,
            actor_rx,
            actor_tx,
            callbacks: Default::default(),
            callback_token: 0,
        })
    }

    fn subscribe(&self) -> mpsc::Sender<ActorMessage> {
        self.actor_tx.clone()
    }

    async fn run(mut self) {
        const DEBOUNCE: Duration = Duration::from_millis(250);

        let mut timer = tokio::time::interval(DEBOUNCE);
        let mut last_event = None;
        let mut wall_time_interval = tokio::time::interval(POLL_WALL_TIME_INTERVAL);

        loop {
            tokio::select! {
                biased;
                _ = timer.tick() => {
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
                        timer.reset_immediately();
                    }
                }
                event = self.actor_rx.recv() => match event {
                    Some(msg) => match msg {
                        ActorMessage::NetworkActivity => {
                            trace!("network activity detected");
                            last_event.replace(false);
                            timer.reset_immediately();
                        }
                        ActorMessage::Subscribe(callback, s) => {
                            let token = self.next_callback_token();
                            self.callbacks.insert(token, Arc::new(callback));
                            s.send(token).ok();
                        }
                        ActorMessage::Unsubscribe(token, s) => {
                            self.callbacks.remove(&token);
                            s.send(()).ok();
                        }
                    }
                    None => {
                        break;
                    }
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

        let mut is_major = is_major_change(old_state, &new_state);
        // Check for time jumps
        if !is_major && time_jumped {
            is_major = true;
        }

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

    for (iname, i) in &s1.interface {
        let Some(ips) = s1.interface_ips.get(iname) else {
            // inconsistent dataset, ignore
            continue;
        };
        if !is_interesting_interface(i.name()) {
            continue;
        }
        let Some(i2) = s2.interface.get(iname) else {
            return true;
        };
        let Some(ips2) = s2.interface_ips.get(iname) else {
            return true;
        };
        if i != i2 || !prefixes_major_equal(ips, ips2) {
            return true;
        }
    }

    false
}

/// Checks wheter `a` and `b` are equal after ignoring uninteresting
/// things, like link-local, loopback and multicast addresses.
fn prefixes_major_equal(a: &[IpNet], b: &[IpNet]) -> bool {
    fn is_interesting(p: &IpNet) -> bool {
        let a = p.addr();
        if is_link_local(a) || a.is_loopback() || a.is_multicast() {
            return false;
        }
        true
    }

    let a = a.iter().filter(|p| is_interesting(p));
    let b = b.iter().filter(|p| is_interesting(p));

    for (a, b) in a.zip(b) {
        if a != b {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;

    use super::*;

    #[tokio::test]
    async fn test_monitor() {
        let _guard = iroh_test::logging::setup();

        let mon = Monitor::new().await.unwrap();
        let _token = mon
            .subscribe(|is_major| {
                async move {
                    println!("CHANGE DETECTED: {}", is_major);
                }
                .boxed()
            })
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}
