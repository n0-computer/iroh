use super::{Error, Role};
use crate::proto::{
    keys::{UserPublicKey, UserSignature},
    wgps::{AccessChallenge, AccessChallengeBytes, ChallengeHash},
};

/// Data from the initial transmission
///
/// This happens before the session is initialized.
#[derive(Debug)]
pub struct InitialTransmission {
    /// The [`AccessChallenge`] nonce, whose hash we sent to the remote.
    pub our_nonce: AccessChallenge,
    /// The [`ChallengeHash`] we received from the remote.
    pub received_commitment: ChallengeHash,
    /// The maximum payload size we received from the remote.
    pub their_max_payload_size: u64,
}

#[derive(Debug)]
pub enum ChallengeState {
    Committed {
        our_nonce: AccessChallenge,
        received_commitment: ChallengeHash,
    },
    Revealed {
        ours: AccessChallengeBytes,
        theirs: AccessChallengeBytes,
    },
}

impl ChallengeState {
    pub fn reveal(&mut self, our_role: Role, their_nonce: AccessChallenge) -> Result<(), Error> {
        match self {
            Self::Committed {
                our_nonce,
                received_commitment,
            } => {
                if their_nonce.hash() != *received_commitment {
                    return Err(Error::BrokenCommittement);
                }
                let ours = match our_role {
                    Role::Alfie => bitwise_xor(our_nonce.to_bytes(), their_nonce.to_bytes()),
                    Role::Betty => {
                        bitwise_xor_complement(our_nonce.to_bytes(), their_nonce.to_bytes())
                    }
                };
                let theirs = bitwise_complement(ours);
                *self = Self::Revealed { ours, theirs };
                Ok(())
            }
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }

    pub fn is_revealed(&self) -> bool {
        matches!(self, Self::Revealed { .. })
    }

    // pub fn sign(&self, secret_key: &UserSecretKey) -> Result<UserSignature, Error> {
    //     let signable = self.signable()?;
    //     let signature = secret_key.sign(&signable);
    //     Ok(signature)
    // }

    pub fn signable(&self) -> Result<[u8; 32], Error> {
        let challenge = self.get_ours()?;
        Ok(*challenge)
    }

    pub fn verify(&self, user_key: &UserPublicKey, signature: &UserSignature) -> Result<(), Error> {
        let their_challenge = self.get_theirs()?;
        user_key.verify(their_challenge, signature)?;
        Ok(())
    }

    fn get_ours(&self) -> Result<&AccessChallengeBytes, Error> {
        match self {
            Self::Revealed { ours, .. } => Ok(ours),
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }

    fn get_theirs(&self) -> Result<&AccessChallengeBytes, Error> {
        match self {
            Self::Revealed { theirs, .. } => Ok(theirs),
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }
}

fn bitwise_xor<const N: usize>(a: [u8; N], b: [u8; N]) -> [u8; N] {
    let mut res = [0u8; N];
    for (i, (x1, x2)) in a.iter().zip(b.iter()).enumerate() {
        res[i] = x1 ^ x2;
    }
    res
}

fn bitwise_complement<const N: usize>(a: [u8; N]) -> [u8; N] {
    let mut res = [0u8; N];
    for (i, x) in a.iter().enumerate() {
        res[i] = !x;
    }
    res
}

fn bitwise_xor_complement<const N: usize>(a: [u8; N], b: [u8; N]) -> [u8; N] {
    let mut res = [0u8; N];
    for (i, (x1, x2)) in a.iter().zip(b.iter()).enumerate() {
        res[i] = !(x1 ^ x2);
    }
    res
}
