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

#[derive(Debug)]
pub struct SessionInit {
    pub user_secret_key: UserSecretKey,
    // TODO: allow multiple capabilities?
    pub capability: ReadCapability,
    // TODO: allow multiple areas of interest?
    pub area_of_interest: AreaOfInterest,
}

#[derive(Debug)]
enum ChallengeState {
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
pub struct Session {
    peer: NodeId,
    our_role: Role,
    _their_maximum_payload_size: usize,
    init: SessionInit,
    challenge: ChallengeState,
    channels: Arc<Channels>,
    state: SessionState,
    our_current_aoi: Option<AreaOfInterestHandle>,
    store_handle: StoreHandle,
}

impl Session {
    pub fn new(
        peer: NodeId,
        our_role: Role,
        our_nonce: AccessChallenge,
        their_maximum_payload_size: usize,
        received_commitment: ChallengeHash,
        init: SessionInit,
        channels: Channels,
        store_handle: StoreHandle,
    ) -> Self {
        let challenge_state = ChallengeState::Committed {
            our_nonce,
            received_commitment,
        };
        let state = SessionStateInner::default();
        let this = Self {
            peer,
            our_role,
            _their_maximum_payload_size: their_maximum_payload_size,
            challenge: challenge_state,
            our_current_aoi: None, // config
            init,
            channels: Arc::new(channels),
            state: Arc::new(Mutex::new(state)),
            store_handle,
        };
        let msg = CommitmentReveal { nonce: our_nonce };
        this.channels
            .sender(LogicalChannel::Control)
            .send(&msg.into())
            .expect("channel not empty at start");
        this
    }

    pub fn notify_complete(&self) -> Arc<Notify> {
        self.state.lock().unwrap().notify_complete()
    }

    pub fn our_role(&self) -> Role {
        self.our_role
    }

    #[instrument(skip_all)]
    pub async fn run_control(&mut self) -> Result<(), Error> {
        loop {
            info!("wait recv");
            let message = self
                .channels
                .receiver(LogicalChannel::Control)
                .read_message_async()
                .await;
            match message {
                None => break,
                Some(message) => {
                    let message = message?;
                    info!(%message, "recv");
                    self.process_control(message).await?;
                    let is_complete = self.state.lock().unwrap().is_complete();
                    debug!(session=%self.peer.fmt_short(), is_complete, "handled");
                }
            }
        }
        debug!("run_control finished");
        Ok(())
    }

    async fn send_control(&self, message: impl Into<Message>) -> Result<(), Error> {
        let message: Message = message.into();
        self.channels
            .sender(LogicalChannel::Control)
            .send_async(&message)
            .await?;
        info!(msg=%message, "sent");
        Ok(())
    }

    async fn setup(&mut self) -> Result<(), Error> {
        let init = &self.init;
        let area_of_interest = init.area_of_interest.clone();
        let capability = init.capability.clone();

        debug!(?init, "init");
        if *capability.receiver() != init.user_secret_key.public_key() {
            return Err(Error::WrongSecretKeyForCapability);
        }

        // TODO: implement private area intersection
        let intersection_handle = 0.into();

        // register read capability
        let signature = self.challenge.sign(&init.user_secret_key)?;
        let our_capability_handle = self
            .state
            .lock()
            .unwrap()
            .our_resources
            .capabilities
            .bind(capability.clone());
        let msg = SetupBindReadCapability {
            capability,
            handle: intersection_handle,
            signature,
        };
        self.send_control(msg).await?;

        // register area of interest
        let msg = SetupBindAreaOfInterest {
            area_of_interest,
            authorisation: our_capability_handle,
        };
        self.send_control(msg.clone()).await?;
        let our_aoi_handle = self
            .state
            .lock()
            .unwrap()
            .our_resources
            .areas_of_interest
            .bind(msg.clone());
        self.our_current_aoi = Some(our_aoi_handle);

        Ok(())
    }

    async fn process_control(&mut self, message: Message) -> Result<(), Error> {
        match message {
            Message::CommitmentReveal(msg) => {
                self.challenge.reveal(self.our_role, msg.nonce)?;
                self.setup().await?;
            }
            Message::SetupBindReadCapability(msg) => {
                msg.capability.validate()?;
                self.challenge
                    .verify(msg.capability.receiver(), &msg.signature)?;
                // TODO: verify intersection handle
                self.state
                    .lock()
                    .unwrap()
                    .their_resources
                    .capabilities
                    .bind(msg.capability);
            }
            Message::SetupBindStaticToken(msg) => {
                self.state
                    .lock()
                    .unwrap()
                    .their_resources
                    .static_tokens
                    .bind(msg.static_token);
            }
            Message::SetupBindAreaOfInterest(msg) => {
                let their_handle = self
                    .state
                    .lock()
                    .unwrap()
                    .setup_bind_area_of_interest(msg)?;
                let start = if self.our_role == Role::Alfie {
                    let our_handle = self
                        .our_current_aoi
                        .clone()
                        .ok_or(Error::InvalidMessageInCurrentState)?;
                    Some((our_handle, their_handle))
                } else {
                    None
                };
                let message = ToActor::InitSession {
                    peer: self.peer,
                    state: self.state.clone(),
                    channels: self.channels.clone(),
                    start,
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

#[derive(Copy, Clone, Debug)]
pub enum Scope {
    Ours,
    Theirs,
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
