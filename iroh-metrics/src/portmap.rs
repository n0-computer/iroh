super::make_metric_recorders! {
    Portmap,

    /*
     * General port mapping metrics
     */
    ProbeRequests:          Counter: "Number of requests to do a port mapping probe.",
    ProbesDone:             Counter: "Number of probing tasks spawned.",

    /*
     * UPnP metrics
     */
    UpnpProbes:             Counter: "Number of UPnP probes executed.",
    UpnpProbesFailed:       Counter: "Number of UPnP probes failed.",
    UpnpGatewayUpdated:     Counter: "Number of UPnP probes that resulted in a known gateway update.",
    UpnpPortmapAttempts:    Counter: "Number of UPnP port mapping attempts.",
    UpnpPortmapFailed:      Counter: "Numbef of UPnP port mapping attempts that failed."
}
