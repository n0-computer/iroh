make_metrics! {
    Iroh,
    RequestsTotal: Counter: "Total number of requests received",
    BytesSent: Counter: "Number of bytes streamed",
    BytesReceived: Counter: "Number of bytes received"
}
