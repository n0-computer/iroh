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
            CommitmentReveal, Fingerprint, LengthyEntry, LogicalChannel, Message, ReadCapability,
            ReconciliationAnnounceEntries, ReconciliationSendEntry, ReconciliationSendFingerprint,
            SetupBindAreaOfInterest, SetupBindReadCapability, SetupBindStaticToken, StaticToken,
            StaticTokenHandle,
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

const LOGICAL_CHANNEL_CAP: usize = 128;

pub mod coroutine;
pub mod resource;
mod util;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("local store failed")]
    Store(#[from] anyhow::Error),
    #[error("wrong secret key for capability")]
    WrongSecretKeyForCapability,
    #[error("missing resource")]
    MissingResource,
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

// #[derive(Debug)]
// pub struct Session {
//     role: Role,
//     _their_maximum_payload_size: usize,
//
//     init: SessionInit,
//     challenge: ChallengeState,
//
//     control_channel: Channel<Message>,
//     reconciliation_channel: Channel<Message>,
//
//     our_resources: ScopedResources,
//     their_resources: ScopedResources,
//     pending_ranges: HashSet<(AreaOfInterestHandle, ThreeDRange)>,
//     pending_entries: Option<u64>,
//
//     reconciliation_started: bool,
//     our_current_aoi: Option<AreaOfInterestHandle>,
// }

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

    // pub fn drain_outbox(&mut self) -> impl Iterator<Item = Message> + '_ {
    //     self.control_channel
    //         .outbox_drain()
    //         .chain(self.reconciliation_channel.outbox_drain())
    // }
    //
    pub fn our_role(&self) -> Role {
        self.our_role
    }

    // pub fn recv(&mut self, message: Message) {
    //     match message.logical_channel() {
    //         LogicalChannel::ControlChannel => self.control_channel.inbox_push_or_drop(message),
    //         LogicalChannel::ReconciliationChannel => {
    //             self.reconciliation_channel.inbox_push_or_drop(message)
    //         }
    //     }
    // }

    // pub fn is_complete(&self) -> bool {
    //     let state = self.state.lock().unwrap();
    //     state.reconciliation_started
    //         && state.pending_ranges.is_empty()
    //         && state.pending_entries.is_none()
    // }

    // pub async fn run(&mut self)

    #[instrument(skip_all)]
    pub async fn run_control(mut self) -> Result<(), Error> {
        loop {
            trace!("wait recv");
            let message = self
                .channels
                .receiver(LogicalChannel::Control)
                .read_message_async()
                .await?;
            match message {
                None => break,
                Some(message) => {
                    info!(%message, "recv");
                    self.process_control(message).await?;
                    let is_complete = self.state.lock().unwrap().is_complete();
                    debug!(session=%self.peer.fmt_short(), is_complete, "handled");
                }
            }
        }
        Ok(())
        // Ok(())
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

    // fn resources_mut(&self, scope: Scope) -> &mut

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

                // }
                // if self.our_role == Role::Alfie {
                //     if let Some(our_handle) = self.our_current_aoi.clone() {
                //         self.init_reconciliation(our_handle, their_handle).await?;
                //     } else {
                //         warn!(
                //             "received area of interest from remote, but no area of interest set on our side"
                //         );
                //     }
                // } else {
                //
                // }
            }
            Message::ControlFreeHandle(_msg) => {
                // TODO: Free handles
            }
            _ => return Err(Error::UnsupportedMessage),
        }
        Ok(())
    }

    // fn bind_static_token(&mut self, static_token: StaticToken) -> StaticTokenHandle {
    //     let (handle, is_new) = self
    //         .our_resources
    //         .static_tokens
    //         .bind_if_new(static_token.clone());
    //     if is_new {
    //         let msg = SetupBindStaticToken { static_token };
    //         self.control_channel
    //             .send(Message::SetupBindStaticToken(msg));
    //     }
    //     handle
    // }

    async fn init_reconciliation(
        &mut self,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
    ) -> Result<(), Error> {
        // let mut state = self.state.lock().unwrap();
        // let our_aoi = state.our_resources.areas_of_interest.get(&our_handle)?;
        // let their_aoi = state.their_resources.areas_of_interest.get(&their_handle)?;
        //
        // let our_capability = state
        //     .our_resources
        //     .capabilities
        //     .get(&our_aoi.authorisation)?;
        // let namespace = our_capability.granted_namespace();
        //
        // let common_aoi = &our_aoi
        //     .area()
        //     .intersection(&their_aoi.area())
        //     .ok_or(Error::AreaOfInterestDoesNotOverlap)?;
        //
        // let range = common_aoi.into_range();
        // state.reconciliation_started = true;
        // drop(state);
        // let range = NamespacedRange {
        //     namespace: namespace.into(),
        //     range,
        // };
        let message = ToActor::InitSession {
            peer: self.peer,
            state: self.state.clone(),
            channels: self.channels.clone(),
            start: Some((our_handle, their_handle)), // send_fingerprint: Some(range),
        };
        self.store_handle.send(message).await?;
        Ok(())
    }

    // fn send_fingerprint(
    //     &mut self,
    //     range: ThreeDRange,
    //     fingerprint: Fingerprint,
    //     our_handle: AreaOfInterestHandle,
    //     their_handle: AreaOfInterestHandle,
    //     is_final_reply_for_range: Option<ThreeDRange>,
    // ) {
    //     self.pending_ranges.insert((our_handle, range.clone()));
    //     let msg = ReconciliationSendFingerprint {
    //         range,
    //         fingerprint,
    //         sender_handle: our_handle,
    //         receiver_handle: their_handle,
    //         is_final_reply_for_range,
    //     };
    //     self.reconciliation_channel.send(msg);
    // }

    // fn announce_empty(
    //     &mut self,
    //     range: ThreeDRange,
    //     our_handle: AreaOfInterestHandle,
    //     their_handle: AreaOfInterestHandle,
    //     want_response: bool,
    //     is_final_reply_for_range: Option<ThreeDRange>,
    // ) -> Result<(), Error> {
    //     if want_response {
    //         self.pending_ranges.insert((our_handle, range.clone()));
    //     }
    //     let msg = ReconciliationAnnounceEntries {
    //         range,
    //         count: 0,
    //         want_response,
    //         will_sort: false,
    //         sender_handle: our_handle,
    //         receiver_handle: their_handle,
    //         is_final_reply_for_range,
    //     };
    //     self.reconciliation_channel
    //         .send(Message::ReconciliationAnnounceEntries(msg));
    //     Ok(())
    // }

    //
    // fn process_reconciliation<S: Store>(
    //     &mut self,
    //     store: &mut S,
    //     message: Message,
    // ) -> Result<(), Error> {
    //     match message {
    //         Message::ReconciliationSendFingerprint(message) => {
    //             self.reconciliation_started = true;
    //             let ReconciliationSendFingerprint {
    //                 range,
    //                 fingerprint: their_fingerprint,
    //                 sender_handle: their_handle,
    //                 receiver_handle: our_handle,
    //                 is_final_reply_for_range,
    //             } = message;
    //
    //             self.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;
    //
    //             let namespace = self.range_is_authorised(&range, &our_handle, &their_handle)?;
    //             let our_fingerprint = store.fingerprint(namespace, &range)?;
    //
    //             // case 1: fingerprint match.
    //             if our_fingerprint == their_fingerprint {
    //                 self.announce_empty(
    //                     range.clone(),
    //                     our_handle,
    //                     their_handle,
    //                     false,
    //                     Some(range.clone()),
    //                 )?;
    //             }
    //             // case 2: fingerprint is empty
    //             else if their_fingerprint.is_empty() {
    //                 self.announce_and_send_entries(
    //                     store,
    //                     namespace,
    //                     &range,
    //                     our_handle,
    //                     their_handle,
    //                     true,
    //                     Some(range.clone()),
    //                     None,
    //                 )?;
    //             }
    //             // case 3: fingerprint doesn't match and is non-empty
    //             else {
    //                 // reply by splitting the range into parts unless it is very short
    //                 self.split_range_and_send_parts(
    //                     store,
    //                     namespace,
    //                     &range,
    //                     our_handle,
    //                     their_handle,
    //                 )?;
    //             }
    //         }
    //         Message::ReconciliationAnnounceEntries(message) => {
    //             let ReconciliationAnnounceEntries {
    //                 range,
    //                 count,
    //                 want_response,
    //                 will_sort: _,
    //                 sender_handle: their_handle,
    //                 receiver_handle: our_handle,
    //                 is_final_reply_for_range,
    //             } = message;
    //             self.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;
    //             if self.pending_entries.is_some() {
    //                 return Err(Error::InvalidMessageInCurrentState);
    //             }
    //             let namespace = self.range_is_authorised(&range, &our_handle, &their_handle)?;
    //             if want_response {
    //                 self.announce_and_send_entries(
    //                     store,
    //                     namespace,
    //                     &range,
    //                     our_handle,
    //                     their_handle,
    //                     false,
    //                     Some(range.clone()),
    //                     None,
    //                 )?;
    //             }
    //             if count != 0 {
    //                 self.pending_entries = Some(count);
    //             }
    //         }
    //         Message::ReconciliationSendEntry(message) => {
    //             let remaining = self
    //                 .pending_entries
    //                 .as_mut()
    //                 .ok_or(Error::InvalidMessageInCurrentState)?;
    //             let ReconciliationSendEntry {
    //                 entry,
    //                 static_token_handle,
    //                 dynamic_token,
    //             } = message;
    //             let static_token = self
    //                 .their_resources
    //                 .static_tokens
    //                 .get(&static_token_handle)?;
    //             // TODO: avoid clone of static token?
    //             let authorisation_token =
    //                 AuthorisationToken::from_parts(static_token.clone(), dynamic_token);
    //             let authorised_entry =
    //                 AuthorisedEntry::try_from_parts(entry.entry, authorisation_token)?;
    //             store.ingest_entry(&authorised_entry)?;
    //
    //             *remaining -= 1;
    //             if *remaining == 0 {
    //                 self.pending_entries = None;
    //             }
    //         }
    //         _ => return Err(Error::UnsupportedMessage),
    //     }
    //     Ok(())
    // }
    //
    // fn range_is_authorised(
    //     &self,
    //     range: &ThreeDRange,
    //     receiver_handle: &AreaOfInterestHandle,
    //     sender_handle: &AreaOfInterestHandle,
    // ) -> Result<NamespaceId, Error> {
    //     let our_namespace = self.handle_to_namespace_id(Scope::Ours, receiver_handle)?;
    //     let their_namespace = self.handle_to_namespace_id(Scope::Theirs, sender_handle)?;
    //     if our_namespace != their_namespace {
    //         return Err(Error::AreaOfInterestNamespaceMismatch);
    //     }
    //     let our_aoi = self.handle_to_aoi(Scope::Ours, receiver_handle)?;
    //     let their_aoi = self.handle_to_aoi(Scope::Theirs, sender_handle)?;
    //
    //     if !our_aoi.area().includes_range(&range) || !their_aoi.area().includes_range(&range) {
    //         return Err(Error::RangeOutsideCapability);
    //     }
    //     Ok(our_namespace.into())
    // }
    //
    // fn resources(&self, scope: Scope) -> &ScopedResources {
    //     match scope {
    //         Scope::Ours => &self.our_resources,
    //         Scope::Theirs => &self.their_resources,
    //     }
    // }

    // fn resources_mut(&mut self, scope: Scope) -> &ScopedResources {
    //     match scope {
    //         Scope::Ours => &mut self.our_resources,
    //         Scope::Theirs => &mut self.their_resources,
    //     }
    // }
    //
    // fn handle_to_capability(
    //     &self,
    //     scope: Scope,
    //     handle: &CapabilityHandle,
    // ) -> Result<&ReadCapability, Error> {
    //     self.resources(scope).capabilities.get(handle)
    // }
    //
    // fn handle_to_aoi(
    //     &self,
    //     scope: Scope,
    //     handle: &AreaOfInterestHandle,
    // ) -> Result<&SetupBindAreaOfInterest, Error> {
    //     self.resources(scope).areas_of_interest.get(handle)
    // }
    //
    // fn handle_to_namespace_id(
    //     &self,
    //     scope: Scope,
    //     handle: &AreaOfInterestHandle,
    // ) -> Result<&NamespacePublicKey, Error> {
    //     let aoi = self.handle_to_aoi(scope, handle)?;
    //     let capability = self.resources(scope).capabilities.get(&aoi.authorisation)?;
    //     Ok(capability.granted_namespace())
    // }
}

#[derive(Copy, Clone, Debug)]
pub enum Scope {
    Ours,
    Theirs,
}

#[derive(Debug)]
pub struct Channel<T> {
    inbox: VecDeque<T>,
    outbox: VecDeque<T>,
    // issued_guarantees: u64,
    // available_guarantees: u64,
}
impl<T: fmt::Debug> Default for Channel<T> {
    fn default() -> Self {
        Self::with_capacity(LOGICAL_CHANNEL_CAP)
    }
}

impl<T: fmt::Debug> Channel<T> {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inbox: VecDeque::with_capacity(cap),
            outbox: VecDeque::with_capacity(cap),
            // issued_guarantees: 0,
            // available_guarantees: 0,
        }
    }

    // pub fn recv_guarantees(&mut self, count: u64) {
    //     self.available_guarantees += count;
    // }
    //
    pub fn can_send(&self) -> bool {
        self.outbox.len() < self.outbox.capacity()
    }

    pub fn send(&mut self, value: impl Into<T>) {
        self.outbox.push_back(value.into());
        // self.available_guarantees -= 1;
    }

    fn outbox_drain(&mut self) -> impl Iterator<Item = T> + '_ {
        self.outbox.drain(..)
    }

    fn inbox_pop(&mut self) -> Option<T> {
        self.inbox.pop_front()
    }

    pub fn inbox_push_or_drop(&mut self, message: T) {
        if let Some(dropped) = self.inbox_push(message) {
            warn!(message=?dropped, "dropping message");
        }
    }
    pub fn inbox_push(&mut self, message: T) -> Option<T> {
        if self.has_inbox_capacity() {
            self.inbox.push_back(message);
            None
        } else {
            Some(message)
        }
    }
    pub fn remaining_inbox_capacity(&self) -> usize {
        // self.inbox.capacity() - self.inbox.len() - self.issued_guarantees as usize
        self.inbox.capacity() - self.inbox.len()
    }

    pub fn has_inbox_capacity(&self) -> bool {
        self.remaining_inbox_capacity() > 0
    }

    // pub fn issuable_guarantees(&self) -> u64 {
    //     self.remaining_inbox_capacity() as u64 - self.issued_guarantees
    // }
    //
    // pub fn issue_all_guarantees(&mut self) -> u64 {
    //     let val = self.issuable_guarantees();
    //     self.issued_guarantees += val;
    //     val
    // }
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
