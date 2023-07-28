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
    // pub topics_joined: Counter,
    // pub topics_left: Counter,
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
            // topics_joined: Counter::new("Number of times we joined a topic"),
            // topics_left: Counter::new("Number of times we left a topic"),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "Iroh Gossip"
    }
}
