use std::pin::Pin;
use std::task::Poll;

use anyhow::Result;
use bytes::Bytes;
use futures::{StreamExt, TryStream};
use http::HeaderMap;
use iroh_metrics::{
    core::{MObserver, MRecorder},
    gateway::{GatewayHistograms, GatewayMetrics},
    observe, record,
};
use iroh_resolver::resolver::{
    CidOrDomain, ContentLoader, Metadata, Out, OutMetrics, OutPrettyReader, Resolver, Source,
};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use tracing::{info, warn};

use crate::handlers::GetParams;
use crate::response::ResponseFormat;

#[derive(Debug, Clone)]
pub struct Client<T: ContentLoader> {
    pub(crate) resolver: Resolver<T>,
}

pub struct PrettyStreamBody<T: ContentLoader>(ReaderStream<OutPrettyReader<T>>, Option<u64>);

#[allow(clippy::large_enum_variant)]
pub enum FileResult<T: ContentLoader> {
    File(PrettyStreamBody<T>),
    Directory(Out),
}

impl<T: ContentLoader + std::marker::Unpin> http_body::Body for PrettyStreamBody<T> {
    type Data = Bytes;
    type Error = String;

    fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        let stream = Pin::new(&mut self.0);
        match stream.try_poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(chunk))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.to_string()))),
            Poll::Ready(None) => Poll::Ready(None),
        }
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        Poll::Ready(Ok(None))
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut size_hint = http_body::SizeHint::new();
        if let Some(size) = self.1 {
            size_hint.set_exact(size);
        }
        size_hint
    }
}

impl<T: ContentLoader + std::marker::Unpin> Client<T> {
    pub fn new(rpc_client: &T) -> Self {
        Self {
            resolver: Resolver::new(rpc_client.clone()),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_file(
        &self,
        path: iroh_resolver::resolver::Path,
        start_time: std::time::Instant,
    ) -> Result<(FileResult<T>, Metadata), String> {
        info!("get file {}", path);
        let res = self
            .resolver
            .resolve(path)
            .await
            .map_err(|e| e.to_string())?;
        record!(
            GatewayMetrics::TimeToFetchFirstBlock,
            start_time.elapsed().as_millis() as u64
        );
        let metadata = res.metadata().clone();
        if metadata.source == Source::Bitswap {
            observe!(
                GatewayHistograms::TimeToFetchFirstBlock,
                start_time.elapsed().as_millis() as f64
            );
        } else {
            observe!(
                GatewayHistograms::TimeToFetchFirstBlockCached,
                start_time.elapsed().as_millis() as f64
            );
        }

        if res.is_dir() {
            let body = FileResult::Directory(res);
            Ok((body, metadata))
        } else {
            let reader = res
                .pretty(self.resolver.clone(), OutMetrics { start: start_time })
                .map_err(|e| e.to_string())?;

            let stream = ReaderStream::new(reader);
            let body = PrettyStreamBody(stream, metadata.size);

            Ok((FileResult::File(body), metadata))
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_file_recursive(
        self,
        path: iroh_resolver::resolver::Path,
        start_time: std::time::Instant,
    ) -> Result<axum::body::Body, String> {
        info!("get file {}", path);
        let (mut sender, body) = axum::body::Body::channel();

        tokio::spawn(async move {
            let res = self.resolver.resolve_recursive(path);
            tokio::pin!(res);

            while let Some(res) = res.next().await {
                match res {
                    Ok(res) => {
                        record!(
                            GatewayMetrics::TimeToFetchFirstBlock,
                            start_time.elapsed().as_millis() as u64
                        );
                        let metadata = res.metadata().clone();
                        if metadata.source == Source::Bitswap {
                            observe!(
                                GatewayHistograms::TimeToFetchFirstBlock,
                                start_time.elapsed().as_millis() as f64
                            );
                        } else {
                            observe!(
                                GatewayHistograms::TimeToFetchFirstBlockCached,
                                start_time.elapsed().as_millis() as f64
                            );
                        }
                        let reader =
                            res.pretty(self.resolver.clone(), OutMetrics { start: start_time });
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
