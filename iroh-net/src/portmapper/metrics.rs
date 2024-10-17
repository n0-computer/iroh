use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};

/// Enum of metrics for the module
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    /*
     * General port mapping metrics
     */
    pub probes_started: Counter,
    pub local_port_updates: Counter,
    pub mapping_attempts: Counter,
    pub mapping_failures: Counter,
    pub external_address_updated: Counter,

    /*
     * UPnP metrics
     */
    pub upnp_probes: Counter,
    pub upnp_probes_failed: Counter,
    pub upnp_available: Counter,
    pub upnp_gateway_updated: Counter,

    /*
     * PCP metrics
     */
    pub pcp_probes: Counter,
    pub pcp_available: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            probes_started: Counter::new("Number of probing tasks started."),
            local_port_updates: Counter::new("Number of updates to the local port."),
            mapping_attempts: Counter::new("Number of mapping tasks started."),
            mapping_failures: Counter::new("Number of failed mapping tasks"),
            external_address_updated: Counter::new(
                "Number of times the external address obtained via port mapping was updated.",
            ),

            /*
             * UPnP metrics
             */
            upnp_probes: Counter::new("Number of UPnP probes executed."),
            upnp_probes_failed: Counter::new("Number of failed Upnp probes"),
            upnp_available: Counter::new("Number of UPnP probes that found it available."),
            upnp_gateway_updated: Counter::new(
                "Number of UPnP probes that resulted in a gateway different to the previous one.",
            ),

            /*
             * PCP metrics
             */
            pcp_probes: Counter::new("Number of PCP probes executed."),
            pcp_available: Counter::new("Number of PCP probes that found it available."),
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "portmap"
    }
}
