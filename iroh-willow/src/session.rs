use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::{Arc, Mutex},
};

use ed25519_dalek::SignatureError;

use iroh_base::{hash::Hash, key::NodeId};
use tokio::sync::Notify;
use tracing::{debug, info, instrument, trace, warn};

use crate::{
    proto::{
        grouping::{AreaOfInterest, NamespacedRange, ThreeDRange},
        keys::{NamespaceId, NamespacePublicKey, UserPublicKey, UserSecretKey, UserSignature},
        meadowcap::InvalidCapability,
        wgps::{
            AccessChallenge, AreaOfInterestHandle, CapabilityHandle, ChallengeHash,
            CommitmentReveal, Fingerprint, HandleType, LengthyEntry, LogicalChannel, Message,
            ReadCapability, ReconciliationAnnounceEntries, ReconciliationSendEntry,
            ReconciliationSendFingerprint, ResourceHandle, SetupBindAreaOfInterest,
            SetupBindReadCapability, SetupBindStaticToken, StaticToken, StaticTokenHandle,
        },
        willow::{AuthorisationToken, AuthorisedEntry, Unauthorised},
    },
    store::{
        actor::{StoreHandle, ToActor},
        SplitAction, Store, SyncConfig,
    },
    util::channel::ReadOutcome,
};

use self::{
    coroutine::{Channels, SessionState, SessionStateInner},
    resource::ScopedResources,
};

pub mod coroutine;
pub mod resource;
mod util;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("local store failed")]
    Store(#[from] anyhow::Error),
    #[error("wrong secret key for capability")]
    WrongSecretKeyForCapability,
    #[error("missing resource {0:?}")]
    MissingResource(ResourceHandle),
    #[error("received capability is invalid")]
    InvalidCapability,
    #[error("received capability has an invalid signature")]
    InvalidSignature,
    #[error("missing resource")]
    RangeOutsideCapability,
    #[error("received a message that is not valid in the current session state")]
    InvalidMessageInCurrentState,
    #[error("our and their area of interests refer to different namespaces")]
    AreaOfInterestNamespaceMismatch,
    #[error("our and their area of interests do not overlap")]
    AreaOfInterestDoesNotOverlap,
    #[error("received an entry which is not authorised")]
    UnauthorisedEntryReceived,
    #[error("received an unsupported message type")]
    UnsupportedMessage,
    #[error("the received nonce does not match the received committment")]
    BrokenCommittement,
    #[error("received an actor message for unknown session")]
    SessionNotFound,
}

impl From<Unauthorised> for Error {
    fn from(_value: Unauthorised) -> Self {
        Self::UnauthorisedEntryReceived
    }
}
impl From<InvalidCapability> for Error {
    fn from(_value: InvalidCapability) -> Self {
        Self::InvalidCapability
    }
}

impl From<SignatureError> for Error {
    fn from(_value: SignatureError) -> Self {
        Self::InvalidSignature
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    Betty,
    Alfie,
}

#[derive(Copy, Clone, Debug)]
pub enum Scope {
    Ours,
    Theirs,
}

#[derive(Debug)]
pub struct SessionInit {
    pub user_secret_key: UserSecretKey,
    // TODO: allow multiple capabilities?
    pub capability: ReadCapability,
    // TODO: allow multiple areas of interest?
    pub area_of_interest: AreaOfInterest,
}

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

#[derive(Debug)]
pub struct ControlLoop {
    init: SessionInit,
    channels: Arc<Channels>,
    state: SessionState,
    store_handle: StoreHandle,
}

impl ControlLoop {
    pub fn new(
        state: SessionStateInner,
        channels: Channels,
        store_handle: StoreHandle,
        init: SessionInit,
    ) -> Self {
        Self {
            init,
            channels: Arc::new(channels),
            state: Arc::new(Mutex::new(state)),
            store_handle,
        }
    }

    #[instrument(skip_all)]
    pub async fn run(mut self) -> Result<(), Error> {
        let reveal_message = self.state.lock().unwrap().commitment_reveal()?;
        self.channels
            .control_send
            .send_async(&reveal_message)
            .await?;
        while let Some(message) = self.channels.control_recv.recv_async().await {
            let message = message?;
            info!(%message, "recv");
            self.on_control_message(message).await?;
        }
        debug!("run_control finished");
        Ok(())
    }

    async fn on_control_message(&mut self, message: Message) -> Result<(), Error> {
        match message {
            Message::CommitmentReveal(msg) => {
                let setup_messages = self
                    .state
                    .lock()
                    .unwrap()
                    .on_commitment_reveal(msg, &self.init)?;
                for message in setup_messages {
                    self.channels.control_send.send_async(&message).await?;
                    info!(%message, "sent");
                }
            }
            Message::SetupBindReadCapability(msg) => {
                self.state
                    .lock()
                    .unwrap()
                    .on_setup_bind_read_capability(msg)?;
            }
            Message::SetupBindStaticToken(msg) => {
                self.state.lock().unwrap().on_setup_bind_static_token(msg);
            }
            Message::SetupBindAreaOfInterest(msg) => {
                let (peer, start) = self
                    .state
                    .lock()
                    .unwrap()
                    .on_setup_bind_area_of_interest(msg)?;
                let message = ToActor::InitSession {
                    state: self.state.clone(),
                    channels: self.channels.clone(),
                    start,
                    peer,
                };
                self.store_handle.send(message).await?;
            }
            Message::ControlFreeHandle(_msg) => {
                // TODO: Free handles
            }
            _ => return Err(Error::UnsupportedMessage),
        }
        Ok(())
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
