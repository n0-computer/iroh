//! Utilities for working with tokio io
use derive_more::Display;
use range_collections::RangeSet2;
use std::{
    io::{self, Read, Seek, Write},
    path::{Component, Path, PathBuf},
    pin::Pin,
    result,
    task::Poll,
};
use thiserror::Error;

use crate::Hash;
use anyhow::Context;
use bao_tree::io::error::EncodeError;
use bao_tree::io::sync::encode_ranges_validated;
use bytes::Bytes;
use futures::{future::LocalBoxFuture, FutureExt};
use iroh_io::AsyncSliceWriter;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::IROH_BLOCK_SIZE;

/// A reader that tracks the number of bytes read
#[derive(Debug)]
pub(crate) struct TrackingReader<R> {
    inner: R,
    read: u64,
}

impl<R> TrackingReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, read: 0 }
    }

    #[allow(dead_code)]
    pub fn bytes_read(&self) -> u64 {
        self.read
    }

    pub fn into_parts(self) -> (R, u64) {
        (self.inner, self.read)
    }
}

impl<R> AsyncRead for TrackingReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let filled0 = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            let size = buf.filled().len().saturating_sub(filled0);
            this.read = this.read.saturating_add(size as u64);
        }
        res
    }
}

/// A writer that tracks the number of bytes written
#[derive(Debug)]
pub(crate) struct TrackingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> TrackingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }

    #[allow(dead_code)]
    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    pub fn into_parts(self) -> (W, u64) {
        (self.inner, self.written)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TrackingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(size)) = res {
            this.written = this.written.saturating_add(size as u64);
        }
        res
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Converts an AsyncWrite into an AsyncSliceWriter by just ignoring the offsets
#[derive(Debug)]
pub struct ConcatenateSliceWriter<W>(W);

impl<W> ConcatenateSliceWriter<W> {
    /// Create a new `ConcatenateSliceWriter` from an inner writer
    pub fn new(inner: W) -> Self {
        Self(inner)
    }

    /// Return the inner writer
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: AsyncWrite + Unpin + 'static> AsyncSliceWriter for ConcatenateSliceWriter<W> {
    type WriteBytesAtFuture<'a> = LocalBoxFuture<'a, io::Result<()>>;
    fn write_bytes_at(&mut self, _offset: u64, data: Bytes) -> Self::WriteBytesAtFuture<'_> {
        async move { self.0.write_all(&data).await }.boxed_local()
    }

    type WriteAtFuture<'a> = LocalBoxFuture<'a, io::Result<()>>;
    fn write_at(&mut self, _offset: u64, bytes: &[u8]) -> Self::WriteAtFuture<'_> {
        let t: smallvec::SmallVec<[u8; 16]> = bytes.into();
        async move { self.0.write_all(&t).await }.boxed_local()
    }

    type SyncFuture<'a> = LocalBoxFuture<'a, io::Result<()>>;
    fn sync(&mut self) -> Self::SyncFuture<'_> {
        self.0.flush().boxed_local()
    }

    type SetLenFuture<'a> = futures::future::Ready<io::Result<()>>;
    fn set_len(&mut self, _len: u64) -> Self::SetLenFuture<'_> {
        futures::future::ready(io::Result::Ok(()))
    }
}

/// converts a canonicalized relative path to a string, returning an error if
/// the path is not valid unicode
///
/// this will also fail if the path is non canonical, i.e. contains `..` or `.`,
/// or if the path components contain any windows or unix path separators
pub fn canonicalize_path(path: impl AsRef<Path>) -> anyhow::Result<String> {
    let parts = path
        .as_ref()
        .components()
        .map(|c| {
            let c = if let Component::Normal(x) = c {
                x.to_str().context("invalid character in path")?
            } else {
                anyhow::bail!("invalid path component {:?}", c)
            };
            anyhow::ensure!(
                !c.contains('/') && !c.contains('\\'),
                "invalid path component {:?}",
                c
            );
            Ok(c)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(parts.join("/"))
}

/// Create a pathbuf from a name.
pub fn pathbuf_from_name(name: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for part in name.split('/') {
        path.push(part);
    }
    path
}

/// Todo: gather more information about validation errors. E.g. offset
///
/// io::Error should be just the fallback when a more specific error is not available.
#[derive(Debug, Display, Error)]
pub enum BaoValidationError {
    /// Generic io error. We were unable to read the data.
    IoError(#[from] std::io::Error),
    /// The data failed to validate
    EncodeError(#[from] EncodeError),
}

/// Validate that the data matches the outboard.
pub fn validate_bao<F: Fn(u64)>(
    hash: Hash,
    data_reader: impl Read + Seek,
    outboard: Bytes,
    progress: F,
) -> result::Result<(), BaoValidationError> {
    let hash = blake3::Hash::from(hash);
    let outboard =
        bao_tree::outboard::PreOrderMemOutboardRef::new(hash, IROH_BLOCK_SIZE, &outboard)?;

    // do not wrap the data_reader in a BufReader, that is slow wnen seeking
    encode_ranges_validated(
        data_reader,
        outboard,
        &RangeSet2::all(),
        DevNull(0, progress),
    )?;
    Ok(())
}

/// little util that discards data but prints progress every 1MB
struct DevNull<F>(u64, F);

impl<F: Fn(u64)> Write for DevNull<F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        const NOTIFY_EVERY: u64 = 1024 * 1024;
        let prev = self.0;
        let curr = prev + buf.len() as u64;
        if prev % NOTIFY_EVERY != curr % NOTIFY_EVERY {
            (self.1)(curr);
        }
        self.0 = curr;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
