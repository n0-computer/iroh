use iroh_base::hash::Hash;

use crate::session::{Error, Role};

use super::{
    keys::{UserPublicKey, UserSecretKey, UserSignature},
    wgps::{AccessChallenge, ChallengeHash},
};

#[derive(Debug)]
pub enum ChallengeState {
    Committed {
        our_nonce: AccessChallenge,
        received_commitment: ChallengeHash,
    },
    Revealed {
        ours: AccessChallenge,
        theirs: AccessChallenge,
    },
}

impl ChallengeState {
    pub fn reveal(&mut self, our_role: Role, their_nonce: AccessChallenge) -> Result<(), Error> {
        match self {
            Self::Committed {
                our_nonce,
                received_commitment,
            } => {
                if Hash::new(&their_nonce).as_bytes() != received_commitment {
                    return Err(Error::BrokenCommittement);
                }
                let ours = match our_role {
                    Role::Alfie => bitwise_xor(*our_nonce, their_nonce),
                    Role::Betty => bitwise_xor_complement(*our_nonce, their_nonce),
                };
                let theirs = bitwise_complement(ours);
                *self = Self::Revealed { ours, theirs };
                Ok(())
            }
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }

    pub fn sign(&self, secret_key: &UserSecretKey) -> Result<UserSignature, Error> {
        let challenge = self.get_ours()?;
        let signature = secret_key.sign(challenge);
        Ok(signature)
    }

    pub fn verify(&self, user_key: &UserPublicKey, signature: &UserSignature) -> Result<(), Error> {
        let their_challenge = self.get_theirs()?;
        user_key.verify(their_challenge, &signature)?;
        Ok(())
    }

    fn get_ours(&self) -> Result<&AccessChallenge, Error> {
        match self {
            Self::Revealed { ours, .. } => Ok(&ours),
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }

    fn get_theirs(&self) -> Result<&AccessChallenge, Error> {
        match self {
            Self::Revealed { theirs, .. } => Ok(&theirs),
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
