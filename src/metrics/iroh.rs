super::make_metric_recorders! {
    Iroh,
    RequestsTotal: Counter: "Total number of requests received",
    BytesSent: Counter: "Number of bytes streamed",
    BytesReceived: Counter: "Number of bytes received"
}
