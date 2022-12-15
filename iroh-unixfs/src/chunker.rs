use std::{
    fmt::{Debug, Display},
    io,
    pin::Pin,
    str::FromStr,
    task,
};

use anyhow::{anyhow, Context};
use bytes::Bytes;
use futures::{stream::BoxStream, Stream};
use tokio::io::AsyncRead;

mod fixed;
mod rabin;

/// Chunks are limited to 1MiB by default
pub const DEFAULT_CHUNK_SIZE_LIMIT: usize = 1024 * 1024;

pub use self::{
    fixed::{Fixed, DEFAULT_CHUNKS_SIZE},
    rabin::Rabin,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Chunker {
    Fixed(Fixed),
    Rabin(Box<Rabin>),
}

impl Display for Chunker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed(c) => write!(f, "Chunker::Fixed({})", c.chunk_size),
            Self::Rabin(_) => write!(f, "Chunker::Rabin"),
        }
    }
}

/// Chunker configuration.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ChunkerConfig {
    /// Fixed sized chunker.
    Fixed(usize),
    /// Rabin chunker.
    Rabin,
}

impl Display for ChunkerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed(chunk_size) => write!(f, "fixed-{chunk_size}"),
            Self::Rabin => write!(f, "rabin"),
        }
    }
}

impl FromStr for ChunkerConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "rabin" {
            return Ok(ChunkerConfig::Rabin);
        }

        if let Some(rest) = s.strip_prefix("fixed") {
            if rest.is_empty() {
                return Ok(ChunkerConfig::Fixed(DEFAULT_CHUNKS_SIZE));
            }

            if let Some(rest) = rest.strip_prefix('-') {
                let chunk_size: usize = rest.parse().context("invalid chunk size")?;
                if chunk_size > DEFAULT_CHUNK_SIZE_LIMIT {
                    return Err(anyhow!("chunk size too large"));
                }

                return Ok(ChunkerConfig::Fixed(chunk_size));
            }
        }

        Err(anyhow!("unknown chunker: {}", s))
    }
}

impl From<ChunkerConfig> for Chunker {
    fn from(cfg: ChunkerConfig) -> Self {
        match cfg {
            ChunkerConfig::Fixed(chunk_size) => Chunker::Fixed(Fixed::new(chunk_size)),
            ChunkerConfig::Rabin => Chunker::Rabin(Box::default()),
        }
    }
}

pub enum ChunkerStream<'a> {
    Fixed(BoxStream<'a, io::Result<Bytes>>),
    Rabin(BoxStream<'a, io::Result<Bytes>>),
}

impl<'a> Debug for ChunkerStream<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed(_) => write!(f, "Fixed(impl Stream<Item=Bytes>)"),
            Self::Rabin(_) => write!(f, "Rabin(impl Stream<Item=Bytes>)"),
        }
    }
}

impl<'a> Stream for ChunkerStream<'a> {
    type Item = io::Result<Bytes>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Option<Self::Item>> {
        match &mut *self {
            Self::Fixed(ref mut stream) => Pin::new(stream).poll_next(cx),
            Self::Rabin(ref mut stream) => Pin::new(stream).poll_next(cx),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Fixed(ref stream) => stream.size_hint(),
            Self::Rabin(ref stream) => stream.size_hint(),
        }
    }
}

impl Chunker {
    pub fn chunks<'a, R: AsyncRead + Unpin + Send + 'a>(self, source: R) -> ChunkerStream<'a> {
        match self {
            Self::Fixed(chunker) => ChunkerStream::Fixed(chunker.chunks(source)),
            Self::Rabin(chunker) => ChunkerStream::Rabin(chunker.chunks(source)),
        }
    }
}
