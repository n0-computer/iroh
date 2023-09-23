//! traits related to collections of blobs
use crate::util::Hash;
use futures::{
    future::{self, LocalBoxFuture},
    FutureExt,
};
use iroh_io::{AsyncSliceReader, AsyncSliceReaderExt};
use std::fmt::Debug;

/// A custom collection parser that allows the user to define what a collection is.
///
/// A collection can be anything that contains an ordered sequence of blake3 hashes.
/// Some collections store links with a fixed size and therefore allow efficient
/// skipping. Others store links with a variable size and therefore only allow
/// sequential access.
///
/// This API tries to accomodate both use cases. For collections that do not allow
/// efficient random access, the [`LinkStream::skip`] method can be implemented by just repeatedly
/// calling `next`.
///
/// For collections that do allow efficient random access, the [`LinkStream::skip`] method can be
/// used to move some internal offset.
pub trait CollectionParser: Send + Debug + Clone + 'static {
    /// Parse a collection with this parser
    fn parse<'a, R: AsyncSliceReader + 'a>(
        &'a self,
        format: u64,
        reader: R,
    ) -> LocalBoxFuture<'a, anyhow::Result<(Box<dyn LinkStream>, CollectionStats)>>;
}

/// A stream (async iterator) over the hashes of a collection.
///
/// Allows to get the next hash or skip a number of hashes.  Does not
/// implement `Stream` because of the extra `skip` method.
pub trait LinkStream: Debug {
    /// Get the next hash in the collection.
    fn next(&mut self) -> LocalBoxFuture<'_, anyhow::Result<Option<Hash>>>;
    /// Skip a number of hashes in the collection.
    fn skip(&mut self, n: u64) -> LocalBoxFuture<'_, anyhow::Result<()>>;
}

/// Information about a collection.
#[derive(Debug, Clone, Copy, Default)]
pub struct CollectionStats {
    /// The number of blobs in the collection. `None` for unknown.
    pub num_blobs: Option<u64>,
    /// The total size of all blobs in the collection. `None` for unknown.
    pub total_blob_size: Option<u64>,
}

/// A collection parser that just disables collections entirely.
#[derive(Debug, Clone)]
pub struct NoCollectionParser;

/// A CustomCollection for NoCollectionParser.
///
/// This is useful for when you don't want to support collections at all.
impl CollectionParser for NoCollectionParser {
    fn parse<'a, R: AsyncSliceReader + 'a>(
        &'a self,
        _format: u64,
        _reader: R,
    ) -> LocalBoxFuture<'a, anyhow::Result<(Box<dyn LinkStream>, CollectionStats)>> {
        future::err(anyhow::anyhow!("collections not supported")).boxed_local()
    }
}

/// A collection parser that parses a sequence of links.
#[derive(Debug, Clone)]
pub struct LinkSeqCollectionParser;

impl CollectionParser for LinkSeqCollectionParser {
    fn parse<'a, R: AsyncSliceReader + 'a>(
        &'a self,
        _format: u64,
        mut reader: R,
    ) -> LocalBoxFuture<'a, anyhow::Result<(Box<dyn LinkStream>, CollectionStats)>> {
        async move {
            let bytes = reader.read_to_end().await?;
            let links = postcard::from_bytes::<Box<[Hash]>>(&bytes)?;
            let stream: Box<dyn LinkStream> = Box::new(ArrayLinkStream::new(links));
            Ok((stream, Default::default()))
        }
        .boxed_local()
    }
}

/// Stream of links that is used by the default collections
///
/// Just contains an array of hashes, so it requires at least all hashes to be loaded into memory.
#[derive(Debug, Clone)]
pub struct ArrayLinkStream {
    hashes: Box<[Hash]>,
    offset: usize,
}

impl ArrayLinkStream {
    /// Create a new iterator over the given hashes.
    pub fn new(hashes: Box<[Hash]>) -> Self {
        Self { hashes, offset: 0 }
    }
}

impl LinkStream for ArrayLinkStream {
    fn next(&mut self) -> LocalBoxFuture<'_, anyhow::Result<Option<Hash>>> {
        let res = if self.offset < self.hashes.len() {
            let hash = self.hashes[self.offset];
            self.offset += 1;
            Some(hash)
        } else {
            None
        };
        future::ok(res).boxed_local()
    }

    fn skip(&mut self, n: u64) -> LocalBoxFuture<'_, anyhow::Result<()>> {
        let res = if let Some(offset) = self
            .offset
            .checked_add(usize::try_from(n).unwrap_or(usize::MAX))
        {
            self.offset = offset;
            Ok(())
        } else {
            Err(anyhow::anyhow!("overflow"))
        };
        future::ready(res).boxed_local()
    }
}
