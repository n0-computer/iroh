//! Monitoring of networking interfaces and route changes.

use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, info, trace, warn};

use crate::net::interfaces::State;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod bsd;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use bsd::RouteMonitor;

/// Monitors networking interface and route changes.
#[derive(Debug)]
pub struct Monitor {
    /// Task handle for the monitor task.
    handle: JoinHandle<()>,
}

impl Monitor {
    /// Create a new monitor.
    pub async fn new() -> Result<Self> {
        let actor = Actor::new().await?;

        let handle = tokio::task::spawn(async move {
            actor.run().await;
        });

        Ok(Monitor { handle })
    }
}

struct Actor {
    /// Latest known interface state.
    interface_state: State,
    /// Latest observed wall time.
    wall_time: Instant,
    /// OS specific monitor.
    route_monitor: RouteMonitor,
    handle: JoinHandle<()>,
    actor_rx: mpsc::Receiver<()>,
}

impl Actor {
    async fn new() -> Result<Self> {
        let interface_state = State::new().await;
        let wall_time = Instant::now();

        let (s, mut r) = mpsc::channel(16);
        let route_monitor = RouteMonitor::new(s).await?;
        let (actor_tx, actor_rx) = mpsc::channel(16);

        let handle = tokio::task::spawn(async move {
            while let Some(_msg) = r.recv().await {
                actor_tx.send(()).await.expect("actor task died");
            }
        });

        Ok(Actor {
            interface_state,
            wall_time,
            route_monitor,
            handle,
            actor_rx,
        })
    }

    async fn run(mut self) {
        const DEBOUNCE: Duration = Duration::from_millis(250);

        let mut timer = tokio::time::interval(DEBOUNCE);
        let mut last_event = None;

        loop {
            tokio::select! {
                biased;
                _ = timer.tick() => {
                    trace!("tick: {:?}", last_event);
                    if let Some(_event) = last_event.take() {
                        if let Err(err) = self.handle_potential_change().await {
                            warn!("failed to handle network changes: {:?}", err);
                        };
                    }
                }
                event = self.actor_rx.recv() => match event {
                    Some(event) => {
                        trace!("change");
                        last_event.replace(event);
                        timer.reset_immediately();
                    }
                    None => {
                        break;
                    }
                }
            }
        }
    }

    async fn handle_potential_change(&mut self) -> Result<()> {
        let new_state = State::new().await;
        info!("potential change");

        // info!("old state: {:#?}", self.interface_state);
        // info!("new state: {:#?}", new_state);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitor() {
        let _guard = iroh_test::logging::setup();

        let mon = Monitor::new().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}
