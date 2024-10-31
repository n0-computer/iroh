use std::fmt;

use serde::{Deserialize, Serialize};
use willow_store::{FixedSize, LiftingCommutativeMonoid, PointRef};

use crate::{
    proto::data_model::Entry,
    store::willow_store_glue::{
        path_to_blobseq, IrohWillowParams, StoredAuthorisedEntry, StoredTimestamp,
    },
};

#[derive(
    Default,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    Clone,
    Copy,
    zerocopy_derive::FromBytes,
    zerocopy_derive::AsBytes,
    zerocopy_derive::FromZeroes,
)]
#[repr(transparent)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub(crate) fn lift_stored_entry(
        key: &PointRef<IrohWillowParams>,
        payload_digest: &[u8; 32],
        payload_size: u64,
    ) -> Self {
        let mut hasher = iroh_blake3::Hasher::default();
        hasher.update(key.as_slice());
        hasher.update(payload_digest);
        hasher.update(&payload_size.to_le_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    pub fn lift_entry(entry: &Entry) -> Self {
        let point = willow_store::Point::<IrohWillowParams>::new(
            entry.subspace_id(),
            &StoredTimestamp::new(entry.timestamp()),
            &path_to_blobseq(entry.path()),
        );
        Self::lift_stored_entry(
            &point,
            entry.payload_digest().0.as_bytes(),
            entry.payload_length(),
        )
    }
}

impl FixedSize for Fingerprint {
    const SIZE: usize = std::mem::size_of::<Self>();
}

impl LiftingCommutativeMonoid<PointRef<IrohWillowParams>, StoredAuthorisedEntry> for Fingerprint {
    fn neutral() -> Self {
        Self([0u8; 32])
    }

    fn lift(key: &PointRef<IrohWillowParams>, value: &StoredAuthorisedEntry) -> Self {
        Self::lift_stored_entry(key, &value.payload_digest, value.payload_size)
    }

    fn combine(&self, other: &Self) -> Self {
        let mut slf = self.clone();
        slf ^= *other;
        slf
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", iroh_base::base32::fmt_short(self.0))
    }
}

impl Fingerprint {
    pub fn add_entry(&mut self, entry: &Entry) {
        // TODO: Don't allocate
        let next = Self::lift_entry(entry);
        *self ^= next;
    }

    pub fn add_entries<'a>(&mut self, iter: impl Iterator<Item = &'a Entry>) {
        for entry in iter {
            self.add_entry(entry);
        }
    }

    pub fn from_entries<'a>(iter: impl Iterator<Item = &'a Entry>) -> Self {
        let mut this = Self::default();
        this.add_entries(iter);
        this
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl std::ops::BitXorAssign for Fingerprint {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= b;
        }
    }
}
