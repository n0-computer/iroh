use std::{fmt::Display, io, pin::Pin, task};

use bytes::Bytes;
use futures::{stream::LocalBoxStream, Stream};
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

pub enum ChunkerStream<'a> {
    Fixed(LocalBoxStream<'a, io::Result<Bytes>>),
    Rabin(LocalBoxStream<'a, io::Result<Bytes>>),
}

unsafe impl<'a> Send for ChunkerStream<'a> {}

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
    pub fn chunks<'a, R: AsyncRead + Unpin + std::marker::Send + 'a>(
        self,
        source: R,
    ) -> ChunkerStream<'a> {
        match self {
            Self::Fixed(chunker) => ChunkerStream::Fixed(chunker.chunks(source)),
            Self::Rabin(chunker) => ChunkerStream::Rabin(chunker.chunks(source)),
        }
    }
}
