//! Metrics for iroh-gossip

use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Enum of metrics for the module
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    pub msgs_ctrl_sent: Counter,
    pub msgs_ctrl_recv: Counter,
    pub msgs_data_sent: Counter,
    pub msgs_data_recv: Counter,
    pub msgs_data_sent_size: Counter,
    pub msgs_data_recv_size: Counter,
    pub msgs_ctrl_sent_size: Counter,
    pub msgs_ctrl_recv_size: Counter,
    pub neighbor_up: Counter,
    pub neighbor_down: Counter,
    pub actor_tick_main: Counter,
    pub actor_tick_rx: Counter,
    pub actor_tick_endpoint: Counter,
    pub actor_tick_dialer: Counter,
    pub actor_tick_dialer_success: Counter,
    pub actor_tick_dialer_failure: Counter,
    pub actor_tick_in_event_rx: Counter,
    pub actor_tick_timers: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            msgs_ctrl_sent: Counter::new("Number of control messages sent"),
            msgs_ctrl_recv: Counter::new("Number of control messages received"),
            msgs_data_sent: Counter::new("Number of data messages sent"),
            msgs_data_recv: Counter::new("Number of data messages received"),
            msgs_data_sent_size: Counter::new("Total size of all data messages sent"),
            msgs_data_recv_size: Counter::new("Total size of all data messages received"),
            msgs_ctrl_sent_size: Counter::new("Total size of all control messages sent"),
            msgs_ctrl_recv_size: Counter::new("Total size of all control messages received"),
            neighbor_up: Counter::new("Number of times we connected to a peer"),
            neighbor_down: Counter::new("Number of times we disconnected from a peer"),
            actor_tick_main: Counter::new("Number of times the main actor loop ticked"),
            actor_tick_rx: Counter::new("Number of times the actor ticked for a message received"),
            actor_tick_endpoint: Counter::new(
                "Number of times the actor ticked for an endpoint event",
            ),
            actor_tick_dialer: Counter::new("Number of times the actor ticked for a dialer event"),
            actor_tick_dialer_success: Counter::new(
                "Number of times the actor ticked for a successful dialer event",
            ),
            actor_tick_dialer_failure: Counter::new(
                "Number of times the actor ticked for a failed dialer event",
            ),
            actor_tick_in_event_rx: Counter::new(
                "Number of times the actor ticked for an incoming event",
            ),
            actor_tick_timers: Counter::new("Number of times the actor ticked for a timer event"),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "gossip"
    }
}
