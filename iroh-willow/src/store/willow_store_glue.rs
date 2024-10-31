//! Code required for willow-rs and willow-store to interface together.

use std::fmt::Display;

use anyhow::Result;
use ed25519_dalek::ed25519;
use iroh_blobs::Hash;
use willow_data_model::grouping::{Range, RangeEnd};
use willow_store::{
    BlobSeq, BlobSeqRef, FixedSize, IsLowerBound, KeyParams, LowerBound, Point, QueryRange,
    QueryRange3d, TreeParams,
};

use crate::proto::{
    data_model::{
        AuthorisationToken, AuthorisedEntry, Component, Entry, NamespaceId, Path, PayloadDigest,
        SubspaceId, Timestamp,
    },
    grouping::Range3d,
    wgps::Fingerprint,
};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    zerocopy_derive::FromBytes,
    zerocopy_derive::AsBytes,
    zerocopy_derive::FromZeroes,
)]
#[repr(packed)]
pub(crate) struct StoredAuthorisedEntry {
    pub(crate) authorisation_token_id: ed25519::SignatureBytes,
    pub(crate) payload_digest: [u8; 32],
    pub(crate) payload_size: u64,
}

impl FixedSize for StoredAuthorisedEntry {
    const SIZE: usize = std::mem::size_of::<Self>();
}

impl StoredAuthorisedEntry {
    pub fn from_authorised_entry(entry: &AuthorisedEntry) -> (Point<IrohWillowParams>, Self) {
        let point = willow_store::Point::<IrohWillowParams>::new(
            entry.entry().subspace_id(),
            &StoredTimestamp::new(entry.entry().timestamp()),
            &path_to_blobseq(entry.entry().path()),
        );
        let entry = Self {
            authorisation_token_id: entry.token().signature.to_bytes(),
            payload_digest: *entry.entry().payload_digest().0.as_bytes(),
            payload_size: entry.entry().payload_length(),
        };
        (point, entry)
    }

    pub fn into_authorised_entry(
        self,
        namespace: NamespaceId,
        key: &Point<IrohWillowParams>,
        auth_token: AuthorisationToken,
    ) -> Result<AuthorisedEntry> {
        Ok(AuthorisedEntry::new(
            self.into_entry(namespace, key)?,
            auth_token,
        )?)
    }

    pub fn into_entry(
        self,
        namespace: NamespaceId,
        key: &Point<IrohWillowParams>,
    ) -> Result<Entry> {
        let subspace = key.x();
        let timestamp = key.y();
        let blobseq = key.z().to_owned();
        let path = blobseq_to_path(&blobseq)?;
        Ok(Entry::new(
            namespace,
            *subspace,
            path,
            timestamp.timestamp(),
            self.payload_size,
            PayloadDigest(Hash::from_bytes(self.payload_digest)),
        ))
    }
}

/// A newtype around memory that represents a timestamp.
///
/// This newtype is needed to avoid alignment issues.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    zerocopy_derive::FromBytes,
    zerocopy_derive::AsBytes,
    zerocopy_derive::FromZeroes,
)]
#[repr(packed)]
pub(crate) struct StoredTimestamp([u8; 8]);

impl LowerBound for StoredTimestamp {
    fn min_value() -> Self {
        Self([0u8; 8])
    }
}

impl IsLowerBound for StoredTimestamp {
    fn is_min_value(&self) -> bool {
        self.0 == [0u8; 8]
    }
}

impl FixedSize for StoredTimestamp {
    const SIZE: usize = std::mem::size_of::<StoredTimestamp>();
}

impl Display for StoredTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.timestamp().fmt(f)
    }
}

// The `StoredTimestamp` needs to be big-endian so the derived
// `Ord` instance on the inner [u8; 8] matches the ord instance
// of the equivalent u64.
// See also the associated proptest in this module.
impl StoredTimestamp {
    pub(crate) fn new(ts: Timestamp) -> Self {
        Self(ts.to_be_bytes())
    }

    pub(crate) fn timestamp(&self) -> Timestamp {
        u64::from_be_bytes(self.0)
    }
}

#[derive(Debug, Default, Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
pub(crate) struct IrohWillowParams;

impl TreeParams for IrohWillowParams {
    type V = StoredAuthorisedEntry;
    type M = Fingerprint;
}

impl KeyParams for IrohWillowParams {
    type X = SubspaceId;
    type Y = StoredTimestamp;
    type ZOwned = BlobSeq;
    type Z = BlobSeqRef;
}

pub(crate) fn path_to_blobseq(path: &Path) -> BlobSeq {
    let path_bytes = path
        .components()
        .map(|component| component.to_vec())
        .collect::<Vec<_>>();

    BlobSeq::from(path_bytes)
}

pub(crate) fn blobseq_to_path(blobseq: &BlobSeq) -> Result<Path> {
    let components = blobseq
        .components()
        .map(|c| {
            Component::new(c)
                .ok_or_else(|| anyhow::anyhow!("Path component exceeded length restriction"))
        })
        .collect::<Result<Vec<_>>>()?;
    let total_length = components.iter().map(|c| c.len()).sum::<usize>();
    let path = Path::new_from_iter(total_length, &mut components.into_iter())?;
    Ok(path)
}

pub(crate) fn to_query(range3d: &Range3d) -> QueryRange3d<IrohWillowParams> {
    let path_start = path_to_blobseq(&range3d.paths().start);
    let path_end = match &range3d.paths().end {
        RangeEnd::Closed(end) => Some(path_to_blobseq(end)),
        RangeEnd::Open => None,
    };
    QueryRange3d {
        x: to_query_range(range3d.subspaces()),
        y: to_query_range(&map_range(range3d.times(), |ts| StoredTimestamp::new(*ts))),
        z: QueryRange::new(path_start, path_end),
    }
}

pub(crate) fn to_query_range<T: Ord + Clone>(range: &Range<T>) -> QueryRange<T> {
    QueryRange::new(
        range.start.clone(),
        match &range.end {
            RangeEnd::Closed(end) => Some(end.clone()),
            RangeEnd::Open => None,
        },
    )
}

pub(crate) fn to_range3d(query_range3d: QueryRange3d<IrohWillowParams>) -> Result<Range3d> {
    let path_max = match query_range3d.z.max {
        Some(max) => RangeEnd::Closed(blobseq_to_path(&max)?),
        None => RangeEnd::Open,
    };
    Ok(Range3d::new(
        to_range(query_range3d.x),
        Range {
            start: blobseq_to_path(&query_range3d.z.min)?,
            end: path_max,
        },
        Range {
            start: query_range3d.y.min.timestamp(),
            end: query_range3d
                .y
                .max
                .map_or(RangeEnd::Open, |ts| RangeEnd::Closed(ts.timestamp())),
        },
    ))
}

fn to_range<T: Ord + Clone>(qr: QueryRange<T>) -> Range<T> {
    Range {
        start: qr.min,
        end: qr.max.map_or(RangeEnd::Open, RangeEnd::Closed),
    }
}

pub(crate) fn map_range<S: Ord, T: Ord>(range: &Range<S>, f: impl Fn(&S) -> T) -> Range<T> {
    Range {
        start: f(&range.start),
        end: match &range.end {
            RangeEnd::Closed(end) => RangeEnd::Closed(f(end)),
            RangeEnd::Open => RangeEnd::Open,
        },
    }
}

#[cfg(test)]
mod tests {
    use proptest::prop_assert_eq;
    use test_strategy::proptest;

    use super::StoredTimestamp;

    #[proptest]
    fn prop_stored_timestamp_ord_matches_u64_ord(num: u64, other: u64) {
        let expected = num.cmp(&other);
        let actual = StoredTimestamp::new(num).cmp(&StoredTimestamp::new(other));
        prop_assert_eq!(expected, actual);
    }
}
