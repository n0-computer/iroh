super::make_metric_recorders! {
    Portmap,

    /*
     * General port mapping metrics
     */
    ProbesStarted:          Counter: "Number of probing tasks started.",
    LocalPortUpdates:       Counter: "Number of updates to the local port.",
    MappingAttempts:        Counter: "Number of mapping tasks started.",
    MappingFailures:        Counter: "Number of failed mapping tasks",
    ExternalAddressUpdated: Counter: "Number of times the external address obtained via port mapping was updated.",

    /*
     * UPnP metrics
     */
    UpnpProbes:             Counter: "Number of UPnP probes executed.",
    UpnpProbesFailed:       Counter: "Number of failed Upnp probes",
    UpnpAvailable:          Counter: "Number of UPnP probes that found it available.",
    UpnpGatewayUpdated:     Counter: "Number of UPnP probes that resulted in a gateway different to the previous one.",

}
