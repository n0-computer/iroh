use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::core::Core;

type BytesBody = http_body_util::Full<hyper::body::Bytes>;

/// Start a HTTP server to report metrics.
pub async fn run(metrics_addr: SocketAddr) -> Result<()> {
    info!("Starting metrics server on {metrics_addr}");
    let listener = TcpListener::bind(metrics_addr).await?;
    loop {
        let (stream, _addr) = listener.accept().await?;
        let io = hyper_util::rt::TokioIo::new(stream);
        tokio::spawn(async move {
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(handler))
                .await
            {
                error!("Error serving metrics connection: {err:#}");
            }
        });
    }
}

/// HTTP handler that will respond with the OpenMetrics encoding of our metrics.
async fn handler(_req: Request<hyper::body::Incoming>) -> Result<Response<BytesBody>> {
    let core = Core::get().ok_or_else(|| anyhow!("metrics disabled"))?;
    core.encode().map_err(anyhow::Error::new).map(|r| {
        Response::builder()
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body_full(r))
            .expect("Failed to build response")
    })
}

/// Creates a new [`BytesBody`] with given content.
fn body_full(content: impl Into<hyper::body::Bytes>) -> BytesBody {
    http_body_util::Full::new(content.into())
}
