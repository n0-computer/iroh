//! Monitoring of networking interfaces and route changes.

use std::time::Instant;

use anyhow::Result;

use crate::net::interfaces::State;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod bsd;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use bsd::RouteMonitor;

/// Monitors networking interface and route changes.
#[derive(Debug)]
pub struct Monitor {
    /// Latest known interface state.
    interface_state: State,
    /// Latest observed wall time.
    wall_time: Instant,
    /// OS specific monitor.
    route_monitor: RouteMonitor,
}

impl Monitor {
    /// Create a new monitor.
    pub async fn new() -> Result<Self> {
        let interface_state = State::new().await;
        let wall_time = Instant::now();
        let route_monitor = RouteMonitor::new().await?;

        Ok(Monitor {
            interface_state,
            wall_time,
            route_monitor,
        })
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
