//! Utility functions and types.
use bao_tree::{io::outboard::PreOrderMemOutboard, BaoTree, ChunkRanges};
use bytes::Bytes;
use derive_more::{Debug, Display, From, Into};
use range_collections::range_set::RangeSetRange;
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, fmt, sync::Arc, time::SystemTime};

use crate::{store::Store, BlobFormat, Hash, HashAndFormat, IROH_BLOCK_SIZE};

pub mod io;
mod mem_or_file;
pub mod progress;
pub use mem_or_file::MemOrFile;
mod sparse_mem_file;
pub use sparse_mem_file::SparseMemFile;

/// A tag
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, Into)]
pub struct Tag(pub Bytes);

#[cfg(feature = "redb")]
mod redb_support {
    use super::Tag;
    use bytes::Bytes;
    use redb::{RedbKey, RedbValue};

    impl RedbValue for Tag {
        type SelfType<'a> = Self;

        type AsBytes<'a> = bytes::Bytes;

        fn fixed_width() -> Option<usize> {
            None
        }

        fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
        where
            Self: 'a,
        {
            Self(Bytes::copy_from_slice(data))
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
        where
            Self: 'a,
            Self: 'b,
        {
            value.0.clone()
        }

        fn type_name() -> redb::TypeName {
            redb::TypeName::new("Tag")
        }
    }

    impl RedbKey for Tag {
        fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
            data1.cmp(data2)
        }
    }
}

impl Borrow<[u8]> for Tag {
    fn borrow(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<String> for Tag {
    fn from(value: String) -> Self {
        Self(Bytes::from(value))
    }
}

impl From<&str> for Tag {
    fn from(value: &str) -> Self {
        Self(Bytes::from(value.to_owned()))
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.as_ref();
        match std::str::from_utf8(bytes) {
            Ok(s) => write!(f, "\"{}\"", s),
            Err(_) => write!(f, "{}", hex::encode(bytes)),
        }
    }
}

struct DD<T: fmt::Display>(T);

impl<T: fmt::Display> fmt::Debug for DD<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Tag").field(&DD(self)).finish()
    }
}

impl Tag {
    /// Create a new tag that does not exist yet.
    pub fn auto(time: SystemTime, exists: impl Fn(&[u8]) -> bool) -> Self {
        let now = chrono::DateTime::<chrono::Utc>::from(time);
        let mut i = 0;
        loop {
            let mut text = format!("auto-{}", now.format("%Y-%m-%dT%H:%M:%S%.3fZ"));
            if i != 0 {
                text.push_str(&format!("-{}", i));
            }
            if !exists(text.as_bytes()) {
                return Self::from(text);
            }
            i += 1;
        }
    }
}

/// A set of merged [`SetTagOption`]s for a blob.
#[derive(Debug, Default)]
pub struct TagSet {
    auto: bool,
    named: Vec<Tag>,
}

impl TagSet {
    /// Insert a new tag into the set.
    pub fn insert(&mut self, tag: SetTagOption) {
        match tag {
            SetTagOption::Auto => self.auto = true,
            SetTagOption::Named(tag) => {
                if !self.named.iter().any(|t| t == &tag) {
                    self.named.push(tag)
                }
            }
        }
    }

    /// Convert the [`TagSet`] into a list of [`SetTagOption`].
    pub fn into_tags(self) -> impl Iterator<Item = SetTagOption> {
        self.auto
            .then_some(SetTagOption::Auto)
            .into_iter()
            .chain(self.named.into_iter().map(SetTagOption::Named))
    }

    /// Apply the tags in the [`TagSet`] to the database.
    pub async fn apply<D: Store>(
        self,
        db: &D,
        hash_and_format: HashAndFormat,
    ) -> std::io::Result<()> {
        let tags = self.into_tags();
        for tag in tags {
            match tag {
                SetTagOption::Named(tag) => {
                    db.set_tag(tag, Some(hash_and_format)).await?;
                }
                SetTagOption::Auto => {
                    db.create_tag(hash_and_format).await?;
                }
            }
        }
        Ok(())
    }
}

/// Option for commands that allow setting a tag
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SetTagOption {
    /// A tag will be automatically generated
    Auto,
    /// The tag is explicitly named
    Named(Tag),
}

/// A trait for things that can track liveness of blobs and collections.
///
/// This trait works together with [TempTag] to keep track of the liveness of a
/// blob or collection.
///
/// It is important to include the format in the liveness tracking, since
/// protecting a collection means protecting the blob and all its children,
/// whereas protecting a raw blob only protects the blob itself.
pub trait LivenessTracker: std::fmt::Debug + Send + Sync + 'static {
    /// Called on clone
    fn on_clone(&self, inner: &HashAndFormat);
    /// Called on drop
    fn on_drop(&self, inner: &HashAndFormat);
}

/// A hash and format pair that is protected from garbage collection.
///
/// If format is raw, this will protect just the blob
/// If format is collection, this will protect the collection and all blobs in it
#[derive(Debug)]
pub struct TempTag {
    /// The hash and format we are pinning
    inner: HashAndFormat,
    /// liveness tracker
    liveness: Option<Arc<dyn LivenessTracker>>,
}

impl TempTag {
    /// Create a new temp tag for the given hash and format
    ///
    /// This should only be used by store implementations.
    ///
    /// The caller is responsible for increasing the refcount on creation and to
    /// make sure that temp tags that are created between a mark phase and a sweep
    /// phase are protected.
    pub fn new(inner: HashAndFormat, liveness: Option<Arc<dyn LivenessTracker>>) -> Self {
        if let Some(liveness) = liveness.as_ref() {
            liveness.on_clone(&inner);
        }
        Self { inner, liveness }
    }

    /// The hash of the pinned item
    pub fn inner(&self) -> &HashAndFormat {
        &self.inner
    }

    /// The hash of the pinned item
    pub fn hash(&self) -> &Hash {
        &self.inner.hash
    }

    /// The format of the pinned item
    pub fn format(&self) -> BlobFormat {
        self.inner.format
    }

    /// Keep the item alive until the end of the process
    pub fn leak(mut self) {
        // set the liveness tracker to None, so that the refcount is not decreased
        // during drop. This means that the refcount will never reach 0 and the
        // item will not be gced until the end of the process.
        self.liveness = None;
    }
}

impl Clone for TempTag {
    fn clone(&self) -> Self {
        Self::new(self.inner, self.liveness.clone())
    }
}

impl Drop for TempTag {
    fn drop(&mut self) {
        if let Some(liveness) = self.liveness.as_ref() {
            liveness.on_drop(&self.inner);
        }
    }
}

/// Get the number of bytes given a set of chunk ranges and the total size.
///
/// If some ranges are out of bounds, they will be clamped to the size.
pub fn total_bytes(ranges: ChunkRanges, size: u64) -> u64 {
    ranges
        .iter()
        .map(|range| {
            let (start, end) = match range {
                RangeSetRange::Range(r) => {
                    (r.start.to_bytes().min(size), r.end.to_bytes().min(size))
                }
                RangeSetRange::RangeFrom(range) => (range.start.to_bytes().min(size), size),
            };
            end.saturating_sub(start)
        })
        .reduce(u64::saturating_add)
        .unwrap_or_default()
}

/// A non-sendable marker type
#[derive(Debug)]
pub(crate) struct NonSend {
    _marker: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl NonSend {
    /// Create a new non-sendable marker.
    #[allow(dead_code)]
    pub const fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

/// copy a limited slice from a slice as a `Bytes`.
pub(crate) fn copy_limited_slice(bytes: &[u8], offset: u64, len: usize) -> Bytes {
    bytes[limited_range(offset, len, bytes.len())]
        .to_vec()
        .into()
}

pub(crate) fn limited_range(offset: u64, len: usize, buf_len: usize) -> std::ops::Range<usize> {
    if offset < buf_len as u64 {
        let start = offset as usize;
        let end = start.saturating_add(len).min(buf_len);
        start..end
    } else {
        0..0
    }
}

/// zero copy get a limited slice from a `Bytes` as a `Bytes`.
#[allow(dead_code)]
pub(crate) fn get_limited_slice(bytes: &Bytes, offset: u64, len: usize) -> Bytes {
    bytes.slice(limited_range(offset, len, bytes.len()))
}

/// Compute raw outboard size, without the size header.
#[allow(dead_code)]
pub(crate) fn raw_outboard_size(size: u64) -> u64 {
    BaoTree::new(size, IROH_BLOCK_SIZE).outboard_size()
}

/// Compute raw outboard, without the size header.
pub(crate) fn raw_outboard(data: &[u8]) -> (Vec<u8>, Hash) {
    let res = PreOrderMemOutboard::create(data, IROH_BLOCK_SIZE);
    (res.data, res.root.into())
}
