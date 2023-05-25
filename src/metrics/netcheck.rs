super::make_metric_recorders! {
    Netcheck,

    StunPacketsDropped: Counter: "Incoming STUN packets dropped due to a full receiving queue.",
    StunPacketsSentIpv4: Counter: "Number of IPv4 STUN packets sent",
    StunPacketsSentIpv6: Counter: "Number of IPv6 STUN packets sent",
    StunPacketsRecvIpv4: Counter: "Number of IPv4 STUN packets received",
    StunPacketsRecvIpv6: Counter: "Number of IPv6 STUN packets received",
    Reports: Counter: "Number of reports executed by netcheck, including full reports",
    ReportsFull: Counter: "Number of full reports executed by netcheck",
    ReportsError: Counter: "Number of executed reports resulting in an error",
}
