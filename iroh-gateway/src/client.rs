use std::pin::Pin;
use std::task::Poll;

use anyhow::Result;
use bytes::Bytes;
use futures::{StreamExt, TryStream};
use http::HeaderMap;
use iroh_car::{CarHeader, CarWriter};
use iroh_metrics::{
    core::{MObserver, MRecorder},
    gateway::{GatewayHistograms, GatewayMetrics},
    observe, record,
};
use iroh_resolver::resolver::{
    CidOrDomain, ContentLoader, Metadata, Out, OutMetrics, OutPrettyReader, Resolver, Source,
};
use tokio::io::{AsyncReadExt, AsyncWrite};
use tokio_util::io::ReaderStream;
use tracing::{info, warn};

use crate::response::ResponseFormat;
use crate::{constants::RECURSION_LIMIT, handlers::GetParams};

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
        let metadata = res.metadata().clone();
        record_ttfb_metrics(start_time, &metadata.source);

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
    pub async fn get_car_recursive(
        self,
        path: iroh_resolver::resolver::Path,
        start_time: std::time::Instant,
    ) -> Result<axum::body::StreamBody<ReaderStream<tokio::io::DuplexStream>>, String> {
        info!("get car {}", path);
        // TODO: Find out what a good buffer size is here.
        let (writer, reader) = tokio::io::duplex(1024 * 64);
        let body = axum::body::StreamBody::new(ReaderStream::new(reader));
        let client = self.clone();
        tokio::task::spawn(async move {
            if let Err(e) = fetch_car_recursive(&client.resolver, path, writer, start_time).await {
                warn!("failed to load recursively: {:?}", e);
            }
        });

        Ok(body)
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
                        let metadata = res.metadata().clone();
                        record_ttfb_metrics(start_time, &metadata.source);
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

async fn fetch_car_recursive<T, W>(
    resolver: &Resolver<T>,
    path: iroh_resolver::resolver::Path,
    writer: W,
    start_time: std::time::Instant,
) -> Result<(), anyhow::Error>
where
    T: ContentLoader,
    W: AsyncWrite + Send + Unpin,
{
    let stream = resolver.resolve_recursive_raw(path, Some(RECURSION_LIMIT));
    tokio::pin!(stream);

    let root = stream
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("root cid not found"))??;

    let header = CarHeader::new_v1(vec![*root.cid()]);
    let mut writer = CarWriter::new(header, writer);
    writer.write(*root.cid(), root.content()).await?;

    while let Some(block) = stream.next().await {
        let block = block?;
        record_ttfb_metrics(start_time, block.source());
        writer.write(*block.cid(), block.content()).await?;
    }
    Ok(())
}

fn record_ttfb_metrics(start_time: std::time::Instant, source: &Source) {
    record!(
        GatewayMetrics::TimeToFetchFirstBlock,
        start_time.elapsed().as_millis() as u64
    );
    if *source == Source::Bitswap {
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
}
