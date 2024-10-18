//! Code required for willow-rs and willow-store to interface together.

use anyhow::Result;
use ed25519_dalek::ed25519;
use iroh_blobs::Hash;
use willow_data_model::grouping::{Range, RangeEnd};
use willow_store::{
    BlobSeq, BlobSeqRef, FixedSize, KeyParams, Point, QueryRange, QueryRange3d, TreeParams,
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
pub(crate) struct StoredAuthorizedEntry {
    pub(crate) authorization_token_id: ed25519::SignatureBytes,
    pub(crate) payload_digest: [u8; 32],
    pub(crate) payload_size: u64,
}

impl FixedSize for StoredAuthorizedEntry {
    const SIZE: usize = std::mem::size_of::<Self>();
}

impl StoredAuthorizedEntry {
    pub fn from_authorised_entry(entry: &AuthorisedEntry) -> (Point<IrohWillowParams>, Self) {
        let point = willow_store::Point::<IrohWillowParams>::new(
            entry.entry().subspace_id(),
            &entry.entry().timestamp(),
            &path_to_blobseq(entry.entry().path()),
        );
        let entry = Self {
            authorization_token_id: entry.token().signature.to_bytes(),
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
        let components = blobseq
            .components()
            .map(|c| Component::new(c).unwrap()) // TODO err
            .collect::<Vec<_>>();
        let total_length = components.iter().map(|c| c.len()).sum::<usize>();
        let path = Path::new_from_iter(total_length, &mut components.into_iter())?;
        Ok(Entry::new(
            namespace,
            *subspace,
            path,
            *timestamp,
            self.payload_size,
            PayloadDigest(Hash::from_bytes(self.payload_digest)),
        ))
    }
}

#[derive(Debug, Default, Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
pub(crate) struct IrohWillowParams;

impl TreeParams for IrohWillowParams {
    type V = StoredAuthorizedEntry;
    type M = Fingerprint;
}

impl KeyParams for IrohWillowParams {
    type X = SubspaceId;
    type Y = Timestamp;
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

pub(crate) fn blobseq_successor(blobseq: &BlobSeq) -> BlobSeq {
    BlobSeq::from(
        blobseq
            .components()
            .map(|slice| slice.to_vec())
            .chain(Some(Vec::new())) // Add an empty path element
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn to_query(range3d: &Range3d) -> QueryRange3d<IrohWillowParams> {
    let path_start = path_to_blobseq(&range3d.paths().start);
    let path_end = match &range3d.paths().end {
        RangeEnd::Closed(end) => Some(path_to_blobseq(end)),
        RangeEnd::Open => None,
    };
    QueryRange3d {
        x: to_query_range(range3d.subspaces()),
        y: to_query_range(range3d.times()),
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
