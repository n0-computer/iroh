//! An [AsyncSliceReader] implementation for HTTP resources, using range requests.
//!
//! Uses the [reqwest](https://docs.rs/reqwest) crate. Somewhat inspired by
//! <https://github.com/fasterthanlime/ubio/blob/main/src/http/mod.rs>
use super::*;
use futures::{future::LocalBoxFuture, FutureExt, Stream, StreamExt, TryStreamExt};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Method, StatusCode, Url,
};
use std::str::FromStr;
use std::{fmt, pin::Pin};

/// A struct that implements [AsyncSliceReader] using HTTP range requests
pub struct HttpAdapter {
    client: reqwest::Client,
    opts: http_adapter::Opts,
    url: Url,
    size: Option<u64>,
}

impl fmt::Debug for HttpAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resource")
            .field("url", &self.url)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl HttpAdapter {
    /// Creates a new [`HttpAdapter`] from a URL
    pub async fn new(url: Url) -> io::Result<Self> {
        Self::with_opts(url, Default::default()).await
    }

    /// Creates a new [`HttpAdapter`] from a URL and options
    pub async fn with_opts(url: Url, opts: http_adapter::Opts) -> io::Result<Self> {
        let client = reqwest::Client::new();

        let mut res = Self {
            client,
            opts,
            url,
            size: None,
        };
        res.len().await?;
        Ok(res)
    }

    async fn head_request(&self) -> Result<reqwest::Response, reqwest::Error> {
        let mut req_builder = self.client.request(Method::HEAD, self.url.clone());
        if let Some(headers) = self.opts.headers.as_ref() {
            for (k, v) in headers.iter() {
                req_builder = req_builder.header(k, v);
            }
        }
        let req = req_builder.build()?;
        let res = self.client.execute(req).await?;
        Ok(res)
    }

    async fn range_request(
        &self,
        from: u64,
        to: Option<u64>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        // to is inclusive, commented out because warp is non spec compliant
        let to = to.and_then(|x| x.checked_add(1));
        let range = match to {
            Some(to) => format!("bytes={from}-{to}"),
            None => format!("bytes={from}-"),
        };
        let mut req_builder = self.client.request(Method::GET, self.url.clone());
        if let Some(headers) = self.opts.headers.as_ref() {
            for (k, v) in headers.iter() {
                req_builder = req_builder.header(k, v);
            }
        }
        req_builder = req_builder.header("range", range);

        let req = req_builder.build()?;
        let res = self.client.execute(req).await?;
        Ok(res)
    }

    async fn get_stream_at(
        &self,
        offset: u64,
        len: usize,
    ) -> io::Result<Pin<Box<dyn Stream<Item = io::Result<Bytes>>>>> {
        if let Some(size) = self.size {
            if offset >= size {
                return Ok(Box::pin(futures::stream::empty()));
            }
        }
        let from = offset;
        let to = offset.checked_add(len as u64);
        // if we have a size, clamp the range
        let from = self.size.map(|size| from.min(size)).unwrap_or(from);
        let to = self
            .size
            .map(|size| to.map(|to| to.min(size)))
            .unwrap_or(to);
        let res = self.range_request(from, to).await.map_err(make_io_error)?;
        if res.status().is_success() {
            Ok(Box::pin(res.bytes_stream().map_err(make_io_error)))
        } else if res.status() == StatusCode::RANGE_NOT_SATISFIABLE {
            // https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/416
            // we requested a range that is out of bounds, just return nothing
            Ok(Box::pin(futures::stream::empty()))
        } else {
            Err(make_io_error(format!("http error {}", res.status())))
        }
    }
}

/// Futures for the [HttpAdapter]
pub mod http_adapter {
    use bytes::BytesMut;

    use super::*;

    newtype_future!(
        /// The future returned by [`HttpAdapter::read_at`]
        ReadAtFuture,
        LocalBoxFuture<'a, io::Result<Bytes>>,
        io::Result<Bytes>
    );

    impl fmt::Debug for ReadAtFuture<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ReadAtFuture").finish_non_exhaustive()
        }
    }

    newtype_future!(
        /// The future returned by [`HttpAdapter::len`]
        LenFuture,
        LocalBoxFuture<'a, io::Result<u64>>,
        io::Result<u64>
    );

    impl fmt::Debug for LenFuture<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("LenFuture").finish_non_exhaustive()
        }
    }

    /// Options for [HttpAdapter]
    #[derive(Debug, Clone, Default)]
    pub struct Opts {
        pub(crate) headers: Option<HeaderMap<HeaderValue>>,
    }

    impl AsyncSliceReader for HttpAdapter {
        type ReadAtFuture<'a> = ReadAtFuture<'a>;

        fn read_at(&mut self, offset: u64, len: usize) -> Self::ReadAtFuture<'_> {
            ReadAtFuture(
                async move {
                    let mut stream = self.get_stream_at(offset, len).await?;
                    let mut res = BytesMut::with_capacity(len.min(1024));
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        res.extend_from_slice(&chunk);
                        if BytesMut::len(&res) >= len {
                            break;
                        }
                    }
                    // we do not want to rely on the server sending the exact amount of bytes
                    res.truncate(len);
                    Ok(res.freeze())
                }
                .boxed_local(),
            )
        }

        type LenFuture<'a> = LenFuture<'a>;

        fn len(&mut self) -> Self::LenFuture<'_> {
            LenFuture(
                async move {
                    let io_err = |text: &str| io::Error::new(io::ErrorKind::Other, text);
                    let head_response = self
                        .head_request()
                        .await
                        .map_err(|_| io_err("head request failed"))?;
                    if !head_response.status().is_success() {
                        return Err(io_err("head request failed"));
                    }
                    let size = head_response
                        .headers()
                        .get("content-length")
                        .ok_or_else(|| io_err("content-length header missing"))?;
                    let text = size
                        .to_str()
                        .map_err(|_| io_err("content-length malformed"))?;
                    let size =
                        u64::from_str(text).map_err(|_| io_err("content-length malformed"))?;
                    self.size = Some(size);
                    Ok(size)
                }
                .boxed_local(),
            )
        }
    }
}
