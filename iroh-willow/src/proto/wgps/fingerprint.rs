use std::fmt;

use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};
use willow_store::{FixedSize, LiftingCommutativeMonoid, PointRef};

use crate::{
    proto::data_model::{Entry, EntryExt},
    store::memory::{StoredAuthorizedEntry, WillowParams},
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

impl FixedSize for Fingerprint {
    const SIZE: usize = 32;
}

impl LiftingCommutativeMonoid<PointRef<WillowParams>, StoredAuthorizedEntry> for Fingerprint {
    fn neutral() -> Self {
        Self([0u8; 32])
    }

    fn lift(_key: &PointRef<WillowParams>, value: &StoredAuthorizedEntry) -> Self {
        Self(value.payload_digest)
    }

    fn combine(&self, other: &Self) -> Self {
        let mut result = Self::neutral();
        result ^= *self;
        result ^= *other;
        result
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
        let encoded = entry.encode_to_vec();
        let next = Fingerprint(*Hash::new(&encoded).as_bytes());
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
