use std::pin::Pin;
use std::task::Poll;

use bytes::Bytes;
use futures::StreamExt;
use futures::TryStream;
use http::HeaderMap;
use iroh_metrics::gateway::Metrics;
use iroh_resolver::resolver::CidOrDomain;
use iroh_resolver::resolver::Metadata;
use iroh_resolver::resolver::OutMetrics;
use iroh_resolver::resolver::OutPrettyReader;
use iroh_resolver::resolver::Resolver;
use iroh_resolver::resolver::Source;
use prometheus_client::registry::Registry;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use tracing::info;
use tracing::warn;

use crate::core::GetParams;
use crate::response::ResponseFormat;

#[derive(Debug, Clone)]
pub struct Client {
    resolver: Resolver<iroh_rpc_client::Client>,
}

pub struct PrettyStreamBody(ReaderStream<OutPrettyReader<iroh_rpc_client::Client>>);

impl http_body::Body for PrettyStreamBody {
    type Data = Bytes;
    type Error = String;

    fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        dbg!("poll_data");
        let stream = Pin::new(&mut self.0);
        let res = match stream.try_poll_next(cx) {
            Poll::Ready(res) => res,
            Poll::Pending => {
                dbg!("pending");
                return Poll::Pending;
            }
        };
        match res {
            Some(Ok(chunk)) => {
                let chunk = chunk.into();

                dbg!(&chunk);
                Poll::Ready(Some(Ok(chunk)))
            }
            Some(Err(err)) => Poll::Ready(Some(Err(err.to_string()))),
            None => {
                dbg!("stream end");
                Poll::Ready(None)
            }
        }
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        Poll::Ready(Ok(None))
    }

    // TODO: implement size_hint
}

impl Client {
    pub fn new(rpc_client: &iroh_rpc_client::Client, registry: &mut Registry) -> Self {
        Self {
            resolver: Resolver::new(rpc_client.clone(), registry),
        }
    }

    #[tracing::instrument(skip(self, metrics))]
    pub async fn get_file(
        &self,
        path: iroh_resolver::resolver::Path,
        start_time: std::time::Instant,
        metrics: &Metrics,
    ) -> Result<(PrettyStreamBody, Metadata), String> {
        info!("get file {}", path);
        let res = self
            .resolver
            .resolve(path)
            .await
            .map_err(|e| e.to_string())?;
        metrics
            .ttf_block
            .set(start_time.elapsed().as_millis() as u64);
        let metadata = res.metadata().clone();
        if metadata.source == Source::Bitswap {
            metrics
                .hist_ttfb
                .observe(start_time.elapsed().as_millis() as f64);
        } else {
            metrics
                .hist_ttfb_cached
                .observe(start_time.elapsed().as_millis() as f64);
        }
        {
            let mut reader = res
                .clone()
                .pretty(
                    self.resolver.clone(),
                    OutMetrics {
                        metrics: metrics.clone(),
                        start: start_time,
                    },
                )
                .map_err(|e| e.to_string())?;
            let mut s = String::new();
            reader.read_to_string(&mut s).await.unwrap();
            dbg!(s);
        }
        {
            let reader = res
                .clone()
                .pretty(
                    self.resolver.clone(),
                    OutMetrics {
                        metrics: metrics.clone(),
                        start: start_time,
                    },
                )
                .map_err(|e| e.to_string())?;

            let mut stream = ReaderStream::new(reader);
            let mut s = String::new();
            while let Some(part) = stream.next().await {
                let part = part.unwrap();
                s.push_str(std::str::from_utf8(&part).unwrap());
            }
            dbg!(s);
        }
        let reader = res
            .pretty(
                self.resolver.clone(),
                OutMetrics {
                    metrics: metrics.clone(),
                    start: start_time,
                },
            )
            .map_err(|e| e.to_string())?;
        // TODO: avoid double indirection (stream of bytes -> asyncread -> stream of bytes)
        let stream = ReaderStream::new(reader);
        let body = PrettyStreamBody(stream);

        Ok((body, metadata))
    }

    #[tracing::instrument(skip(self, metrics))]
    pub async fn get_file_recursive(
        self,
        path: iroh_resolver::resolver::Path,
        start_time: std::time::Instant,
        metrics: Metrics,
    ) -> Result<axum::body::Body, String> {
        info!("get file {}", path);
        let (mut sender, body) = axum::body::Body::channel();

        tokio::spawn(async move {
            let res = self.resolver.resolve_recursive(path);
            tokio::pin!(res);

            while let Some(res) = res.next().await {
                match res {
                    Ok(res) => {
                        metrics
                            .ttf_block
                            .set(start_time.elapsed().as_millis() as u64);
                        let metadata = res.metadata().clone();
                        if metadata.source == Source::Bitswap {
                            metrics
                                .hist_ttfb
                                .observe(start_time.elapsed().as_millis() as f64);
                        } else {
                            metrics
                                .hist_ttfb_cached
                                .observe(start_time.elapsed().as_millis() as f64);
                        }
                        let reader = res.pretty(
                            self.resolver.clone(),
                            OutMetrics {
                                metrics: metrics.clone(),
                                start: start_time,
                            },
                        );
                        match reader {
                            Ok(mut reader) => {
                                let mut bytes = Vec::new();
                                reader.read_to_end(&mut bytes).await.unwrap();
                                sender.send_data(bytes.into()).await.unwrap();
                            }
                            Err(e) => {
                                warn!("failed to load recursively: {:?}", e);
                                sender.abort();
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("failed to load recursively: {:?}", e);
                        sender.abort();
                        break;
                    }
                }
            }
        });

        Ok(body)
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub format: ResponseFormat,
    pub cid: CidOrDomain,
    pub resolved_path: iroh_resolver::resolver::Path,
    pub query_file_name: String,
    pub content_path: String,
    pub download: bool,
    pub query_params: GetParams,
}
