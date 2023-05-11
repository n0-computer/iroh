make_metric_recorders! {
    Magicsock,
    RebindCalls:     Counter: "rebind_calls",
    ReStunCalls:     Counter: "restun_calls",
    UpdateEndpoints: Counter: "update_endpoints",

    // Sends (data or disco)
    SendDerpQueued:      Counter: "send_derp_queued",
    SendDerpErrorChan:   Counter: "send_derp_error_chan",
    SendDerpErrorClosed: Counter: "send_derp_error_closed",
    SendDerpErrorQueue:  Counter: "send_derp_error_queue",
    SendUdp:             Counter: "send_udp",
    SendUdpError:        Counter: "send_udp_error",
    SendDerp:            Counter: "send_derp",
    SendDerpError:       Counter: "send_derp_error",

     // Data packets (non-disco)
    SendData:            Counter: "send_data",
    SendDataNetworkDown: Counter: "send_data_network_down",
    RecvDataDerp:        Counter: "recv_data_derp",
    RecvDataIPv4:        Counter: "recv_data_ipv4",
    RecvDataIPv6:        Counter: "recv_data_ipv6",

     // Disco packets
    SendDiscoUdp:         Counter: "disco_send_udp",
    SendDiscoDerp:        Counter: "disco_send_derp",
    SentDiscoUdp:         Counter: "disco_sent_udp",
    SentDiscoDerp:        Counter: "disco_sent_derp",
    SentDiscoPing:        Counter: "disco_sent_ping",
    SentDiscoPong:        Counter: "disco_sent_pong",
    SentDiscoCallMeMaybe: Counter: "disco_sent_callmemaybe",
    RecvDiscoBadPeer:     Counter: "disco_recv_bad_peer",
    RecvDiscoBadKey:      Counter: "disco_recv_bad_key",
    RecvDiscoBadParse:    Counter: "disco_recv_bad_parse",

    RecvDiscoUdp:                 Counter: "disco_recv_udp",
    RecvDiscoDerp:                Counter: "disco_recv_derp",
    RecvDiscoPing:                Counter: "disco_recv_ping",
    RecvDiscoPong:                Counter: "disco_recv_pong",
    RecvDiscoCallMeMaybe:         Counter: "disco_recv_callmemaybe",
    RecvDiscoCallMeMaybeBadNode:  Counter: "disco_recv_callmemaybe_bad_node",
    RecvDiscoCallMeMaybeBadDisco: Counter: "disco_recv_callmemaybe_bad_disco",

    // How many times our DERP home region DI has changed from non-zero to a different non-zero.
    DerpHomeChange: Counter: "derp_home_change"
}

make_metric_observers! {
    MagicsockHist,
    NumPeers:      Gauge: "netmap_num_peers",
    NumDerpConns:  Gauge: "num_derp_conns"
}
