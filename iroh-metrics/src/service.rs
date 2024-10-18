use std::{
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use hyper::{service::service_fn, Request, Response};
use tokio::{io::AsyncWriteExt as _, net::TcpListener};
use tracing::{debug, error, info, warn};

use crate::{core::Core, parse_prometheus_metrics};

type BytesBody = http_body_util::Full<hyper::body::Bytes>;

/// Start a HTTP server to report metrics.
pub async fn run(metrics_addr: SocketAddr) -> Result<()> {
    info!("Starting metrics server on {metrics_addr}");
    let listener = TcpListener::bind(metrics_addr)
        .await
        .with_context(|| format!("failed to bind metrics on {metrics_addr}"))?;
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

/// Start a metrics dumper loop to write metrics to an output file.
pub async fn dumper(path: &PathBuf, interval_ms: Duration) -> Result<()> {
    info!(file = %path.display(), ?interval_ms, "running metrics dumper");
    let _ = Core::get().ok_or_else(|| anyhow!("metrics disabled"))?;

    let start = Instant::now();

    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .await?;

    let mut file = tokio::io::BufWriter::new(file);

    // Dump metrics once with a header
    dump_metrics(&mut file, &start, true).await?;
    loop {
        dump_metrics(&mut file, &start, false).await?;
        tokio::time::sleep(interval_ms).await;
    }
}

/// Dump metrics to a file.
async fn dump_metrics(
    file: &mut tokio::io::BufWriter<tokio::fs::File>,
    start: &Instant,
    write_header: bool,
) -> Result<()> {
    let core = Core::get().ok_or_else(|| anyhow!("metrics disabled"))?;
    let m = core.encode();
    match m {
        Err(e) => error!("Failed to encode metrics: {e:#}"),
        Ok(m) => {
            let m = parse_prometheus_metrics(&m)?;
            let time_since_start = start.elapsed().as_millis() as f64;

            // take the keys from m and sort them
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();

            let mut metrics = String::new();
            if write_header {
                metrics.push_str("time");
                for key in keys.iter() {
                    metrics.push(',');
                    metrics.push_str(key);
                }
                metrics.push('\n');
            }

            metrics.push_str(&format!("{}", time_since_start));
            for key in keys.iter() {
                let value = m[*key];
                let formatted_value = format!("{:.3}", value);
                metrics.push(',');
                metrics.push_str(&formatted_value);
            }
            metrics.push('\n');

            file.write_all(metrics.as_bytes()).await?;
            file.flush().await?;
        }
    }
    Ok(())
}

/// Export metrics to a push gateway.
pub async fn exporter(
    gateway_endpoint: String,
    service_name: String,
    instance_name: String,
    username: Option<String>,
    password: String,
    interval: Duration,
) {
    let Some(core) = Core::get() else {
        error!("metrics disabled");
        return;
    };
    let push_client = reqwest::Client::new();
    let prom_gateway_uri = format!(
        "{}/metrics/job/{}/instance/{}",
        gateway_endpoint, service_name, instance_name
    );
    loop {
        tokio::time::sleep(interval).await;
        let buff = core.encode();
        match buff {
            Err(e) => error!("Failed to encode metrics: {e:#}"),
            Ok(buff) => {
                let mut req = push_client.post(&prom_gateway_uri);
                if let Some(username) = username.clone() {
                    req = req.basic_auth(username, Some(password.clone()));
                }
                let res = match req.body(buff).send().await {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("failed to push metrics: {}", e);
                        continue;
                    }
                };
                match res.status() {
                    reqwest::StatusCode::OK => {
                        debug!("pushed metrics to gateway");
                    }
                    _ => {
                        warn!("failed to push metrics to gateway: {:?}", res);
                        let body = res.text().await.unwrap();
                        warn!("error body: {}", body);
                    }
                }
            }
        }
    }
}
