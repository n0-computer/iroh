use iroh_base::base32::fmt_short;
use iroh_blobs::Hash;
use rand::Rng;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::proto::data_model::DIGEST_LENGTH;

pub const CHALLENGE_LENGTH: usize = 32;
pub const CHALLENGE_HASH_LENGTH: usize = DIGEST_LENGTH;

#[derive(derive_more::Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChallengeHash(#[debug("{}..", fmt_short(self.0))] [u8; CHALLENGE_HASH_LENGTH]);

impl ChallengeHash {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; CHALLENGE_HASH_LENGTH]) -> Self {
        Self(bytes)
    }
}

#[derive(derive_more::Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct AccessChallenge(#[debug("{}..", fmt_short(self.0))] AccessChallengeBytes);

pub type AccessChallengeBytes = [u8; CHALLENGE_LENGTH];

impl Default for AccessChallenge {
    fn default() -> Self {
        Self::generate()
    }
}

impl AccessChallenge {
    pub fn generate() -> Self {
        Self(rand::random())
    }

    pub fn generate_with_rng(rng: &mut impl CryptoRngCore) -> Self {
        Self(rng.gen())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn hash(&self) -> ChallengeHash {
        ChallengeHash(*Hash::new(self.0).as_bytes())
    }
}
