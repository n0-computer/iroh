use core::fmt;
use std::collections::{hash_map, HashMap, VecDeque};

use anyhow::bail;
use ed25519_dalek::SignatureError;
use tracing::{debug, warn};

use crate::{
    proto::{
        keys::{NamespaceId, NamespacePublicKey, UserSecretKey, UserSignature},
        meadowcap::{is_authorised_write, InvalidCapability},
        wgps::{
            AccessChallenge, Area, AreaOfInterest, AreaOfInterestHandle, CapabilityHandle,
            ChallengeHash, CommitmentReveal, ControlAbsolve, ControlAnnounceDropping,
            ControlApologise, ControlFreeHandle, ControlIssueGuarantee, ControlPlead, Fingerprint,
            Handle, HandleType, IntersectionHandle, LengthyEntry, LogicalChannel, Message,
            ReadCapability, ReconciliationAnnounceEntries, ReconciliationSendEntry,
            ReconciliationSendFingerprint, SetupBindAreaOfInterest, SetupBindReadCapability,
            SetupBindStaticToken, StaticToken, StaticTokenHandle, ThreeDRange,
            CHALLENGE_HASH_LENGTH,
        },
        willow::{
            AuthorisationToken, AuthorisedEntry, Entry, PossiblyAuthorisedEntry, Unauthorised,
        },
    },
    store::{RangeSplitPart, Store},
};

#[derive(Debug)]
struct ResourceMap<H, R> {
    next_handle: u64,
    map: HashMap<H, Resource<R>>,
}

impl<H, R> Default for ResourceMap<H, R> {
    fn default() -> Self {
        Self {
            next_handle: 0,
            map: Default::default(),
        }
    }
}

#[derive(Debug)]
enum ResourceState {
    Active,
    WeProposedFree,
    ToBeDeleted,
}

impl<H, R> ResourceMap<H, R>
where
    H: Handle,
    R: Eq + PartialEq,
{
    pub fn bind(&mut self, resource: R) -> H {
        let handle: H = self.next_handle.into();
        self.next_handle += 1;
        let resource = Resource::new(resource);
        self.map.insert(handle, resource);
        handle
    }

    pub fn bind_if_new(&mut self, resource: R) -> (H, bool) {
        // TODO: Optimize / find out if reverse index is better than find_map
        if let Some(handle) = self
            .map
            .iter()
            .find_map(|(handle, r)| (r.value == resource).then_some(handle))
        {
            (*handle, false)
        } else {
            let handle = self.bind(resource);
            (handle, true)
        }
    }

    pub fn get(&self, handle: &H) -> Option<&R> {
        self.map.get(handle).as_ref().map(|r| &r.value)
    }

    pub fn try_get(&self, handle: &H) -> Result<&R, Error> {
        self.get(handle).ok_or(Error::MissingResource)
    }
}

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

#[derive(Debug)]
struct Resource<V> {
    value: V,
    state: ResourceState,
    unprocessed_messages: usize,
}
impl<V> Resource<V> {
    pub fn new(value: V) -> Self {
        Self {
            value,
            state: ResourceState::Active,
            unprocessed_messages: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    Betty,
    Alfie,
}

#[derive(Debug)]
pub struct Session {
    our_role: Role,
    our_nonce: AccessChallenge,
    init: Option<SessionInit>,
    challenge: Option<Challenges>,

    their_maximum_payload_size: usize,
    received_commitment: ChallengeHash,

    control_channel: Channel<Message>,
    reconciliation_channel: Channel<Message>,

    our_current_aoi: Option<AreaOfInterestHandle>,

    us: PeerState,
    them: PeerState,

    done: bool,
}

#[derive(Debug)]
pub struct Challenges {
    ours: AccessChallenge,
    theirs: AccessChallenge,
}

impl Challenges {
    pub fn from_nonces(
        our_role: Role,
        our_nonce: AccessChallenge,
        their_nonce: AccessChallenge,
    ) -> Self {
        let ours = match our_role {
            Role::Alfie => bitwise_xor(our_nonce, their_nonce),
            Role::Betty => bitwise_xor_complement(our_nonce, their_nonce),
        };
        let theirs = bitwise_complement(ours);
        Self { ours, theirs }
    }
}

#[derive(Debug, Default)]
pub struct PeerState {
    capabilities: ResourceMap<CapabilityHandle, ReadCapability>,
    areas_of_interest: ResourceMap<AreaOfInterestHandle, SetupBindAreaOfInterest>,
    static_tokens: ResourceMap<StaticTokenHandle, StaticToken>,
    reconciliation_announce_entries: Option<ReconciliationAnnounceEntries>, // intersections: ResourceMap<IntersectionHandle, intersections>,
}

#[derive(Debug)]
pub struct SessionInit {
    pub user_secret_key: UserSecretKey,
    // TODO: allow multiple capabilities
    pub capability: ReadCapability,
    // TODO: allow multiple areas of interest
    pub area_of_interest: AreaOfInterest,
}

impl Session {
    pub fn new(
        our_role: Role,
        our_nonce: AccessChallenge,
        their_maximum_payload_size: usize,
        received_commitment: ChallengeHash,
        init: SessionInit,
    ) -> Self {
        let mut this = Self {
            our_role,
            our_nonce,
            challenge: None,
            their_maximum_payload_size,
            received_commitment,
            control_channel: Default::default(),
            reconciliation_channel: Default::default(),
            us: Default::default(),
            them: Default::default(),
            our_current_aoi: None, // config
            init: Some(init),
            done: false,
        };
        let msg = CommitmentReveal { nonce: our_nonce };
        this.control_channel.send(msg);
        this
    }

    fn sign_challenge(&self, secret_key: &UserSecretKey) -> Result<UserSignature, Error> {
        let challenge = self
            .challenge
            .as_ref()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        let signature = secret_key.sign(&challenge.ours);
        Ok(signature)
    }

    pub fn drain_outbox(&mut self) -> impl Iterator<Item = Message> + '_ {
        self.control_channel
            .outbox_drain()
            .chain(self.reconciliation_channel.outbox_drain())
    }

    pub fn init(&mut self, init: &SessionInit) -> Result<(), Error> {
        let area_of_interest = init.area_of_interest.clone();
        let capability = init.capability.clone();

        debug!(role=?self.our_role, ?init, "init");
        if *capability.receiver() != init.user_secret_key.public_key() {
            return Err(Error::WrongSecretKeyForCapability);
        }

        // TODO: implement private area intersection
        let intersection_handle = 0.into();

        // register read capability
        let signature = self.sign_challenge(&init.user_secret_key)?;
        let our_capability_handle = self.us.capabilities.bind(capability.clone());
        let msg = SetupBindReadCapability {
            capability,
            handle: intersection_handle,
            signature,
        };
        self.control_channel.send(msg);

        // register area of interest
        let msg = SetupBindAreaOfInterest {
            area_of_interest,
            authorisation: our_capability_handle,
        };
        let our_aoi_handle = self.us.areas_of_interest.bind(msg.clone());
        self.control_channel.send(msg);
        self.our_current_aoi = Some(our_aoi_handle);

        Ok(())
    }

    pub fn our_role(&self) -> Role {
        self.our_role
    }

    pub fn recv(&mut self, message: Message) {
        match message.logical_channel() {
            LogicalChannel::ControlChannel => self.control_channel.inbox_push_or_drop(message),
            LogicalChannel::ReconciliationChannel => {
                self.reconciliation_channel.inbox_push_or_drop(message)
            }
        }
    }

    pub fn process<S: Store>(&mut self, store: &mut S) -> Result<bool, Error> {
        while let Some(message) = self.control_channel.inbox_pop() {
            self.process_control(store, message)?;
        }
        while let Some(message) = self.reconciliation_channel.inbox_pop() {
            self.process_reconciliation(store, message)?;
        }
        Ok(self.done)
    }

    fn process_control<S: Store>(&mut self, store: &mut S, message: Message) -> Result<(), Error> {
        match message {
            Message::CommitmentReveal(msg) => {
                if self.challenge.is_some() {
                    return Err(Error::InvalidMessageInCurrentState);
                }
                self.challenge = Some(Challenges::from_nonces(
                    self.our_role,
                    self.our_nonce,
                    msg.nonce,
                ));
                if let Some(init) = self.init.take() {
                    self.init(&init)?;
                } else {
                    return Err(Error::InvalidMessageInCurrentState);
                }
            }
            Message::SetupBindReadCapability(msg) => {
                let challenge = self
                    .challenge
                    .as_ref()
                    .ok_or(Error::InvalidMessageInCurrentState)?;
                msg.capability.validate()?;
                msg.capability
                    .receiver()
                    .verify(&challenge.theirs, &msg.signature)?;
                // TODO: verify intersection handle
                self.them.capabilities.bind(msg.capability);
            }
            Message::SetupBindStaticToken(msg) => {
                self.them.static_tokens.bind(msg.static_token);
            }
            Message::SetupBindAreaOfInterest(msg) => {
                let capability = self.them.capabilities.try_get(&msg.authorisation)?;
                capability.try_granted_area(&msg.area_of_interest.area)?;
                let their_aoi_handle = self.them.areas_of_interest.bind(msg);

                if self.our_role == Role::Alfie {
                    if let Some(our_aoi_handle) = self.our_current_aoi.clone() {
                        self.init_reconciliation(store, &our_aoi_handle, &their_aoi_handle)?;
                    } else {
                        warn!(
                            "received area of interest from remote, but nothing setup on our side"
                        );
                    }
                }
            }
            Message::ControlFreeHandle(_msg) => {
                // TODO: Free handles
            }
            _ => return Err(Error::UnsupportedMessage),
        }
        Ok(())
    }

    pub fn bind_static_token(&mut self, static_token: StaticToken) -> StaticTokenHandle {
        let (handle, is_new) = self.us.static_tokens.bind_if_new(static_token.clone());
        if is_new {
            let msg = SetupBindStaticToken { static_token };
            self.control_channel
                .send(Message::SetupBindStaticToken(msg));
        }
        handle
    }

    /// Uses the blocking [`Store`] and thus may only be called in the worker thread.
    pub fn init_reconciliation<S: Store>(
        &mut self,
        store: &mut S,
        our_aoi_handle: &AreaOfInterestHandle,
        their_aoi_handle: &AreaOfInterestHandle,
    ) -> Result<(), Error> {
        let our_aoi = self.us.areas_of_interest.try_get(&our_aoi_handle)?;
        let their_aoi = self.us.areas_of_interest.try_get(&their_aoi_handle)?;

        let our_capability = self.us.capabilities.try_get(&our_aoi.authorisation)?;
        let namespace = our_capability.granted_namespace();

        // TODO: intersect with their_aoi first
        let area = &our_aoi
            .area()
            .intersection(&their_aoi.area())
            .ok_or(Error::AreaOfInterestDoesNotOverlap)?;

        let range = area.into_range();
        let fingerprint = store.range_fingerprint(namespace.into(), &range)?;
        let msg = ReconciliationSendFingerprint {
            range,
            fingerprint,
            sender_handle: *our_aoi_handle,
            receiver_handle: *their_aoi_handle,
        };
        self.reconciliation_channel.send(msg);
        Ok(())
    }

    // fn send_fingerprint<S>(&mut self, store: &mut S, )

    fn announce_entries<S: Store>(
        &mut self,
        store: &mut S,
        namespace: NamespaceId,
        range: &ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        want_response: bool,
    ) -> Result<(), Error> {
        for part in store.split_range(namespace, &range)?.into_iter() {
            match part {
                RangeSplitPart::SendFingerprint(range, fingerprint) => {
                    let msg = ReconciliationSendFingerprint {
                        range,
                        fingerprint,
                        sender_handle: our_handle,
                        receiver_handle: their_handle,
                    };
                    self.reconciliation_channel
                        .send(Message::ReconciliationSendFingerprint(msg));
                }
                RangeSplitPart::SendEntries(range, local_count) => {
                    let msg = ReconciliationAnnounceEntries {
                        range: range.clone(),
                        count: local_count,
                        want_response,
                        will_sort: false, // todo: sorted?
                        sender_handle: our_handle,
                        receiver_handle: their_handle,
                    };
                    self.reconciliation_channel.send(msg);
                    for authorised_entry in store.get_entries_with_authorisation(namespace, &range)
                    {
                        let authorised_entry = authorised_entry?;
                        let (entry, token) = authorised_entry.into_parts();
                        let (static_token, dynamic_token) = token.into_parts();
                        // todo: partial entries
                        let available = entry.payload_length;
                        let static_token_handle = self.bind_static_token(static_token);
                        let msg = ReconciliationSendEntry {
                            entry: LengthyEntry::new(entry, available),
                            static_token_handle,
                            dynamic_token,
                        };
                        self.reconciliation_channel.send(msg);
                    }
                }
            }
        }
        Ok(())
    }

    /// Uses the blocking [`Store`] and thus may only be called in the worker thread.
    fn process_reconciliation<S: Store>(
        &mut self,
        store: &mut S,
        message: Message,
    ) -> Result<(), Error> {
        match message {
            Message::ReconciliationSendFingerprint(message) => {
                let ReconciliationSendFingerprint {
                    range,
                    fingerprint,
                    sender_handle,
                    receiver_handle,
                } = message;

                let namespace =
                    self.range_is_authorised(&range, &receiver_handle, &sender_handle)?;
                let our_fingerprint = store.range_fingerprint(namespace, &range)?;

                // case 1: fingerprint match.
                if our_fingerprint == fingerprint {
                    let msg = ReconciliationAnnounceEntries {
                        range,
                        count: 0,
                        want_response: false,
                        will_sort: false,
                        sender_handle,
                        receiver_handle,
                    };
                    self.reconciliation_channel
                        .send(Message::ReconciliationAnnounceEntries(msg));
                    // TODO: This is likely incorrect
                    self.done = true;
                } else {
                    self.announce_entries(
                        store,
                        namespace,
                        &range,
                        receiver_handle,
                        sender_handle,
                        true,
                    )?;
                }
            }
            Message::ReconciliationAnnounceEntries(message) => {
                let ReconciliationAnnounceEntries {
                    range,
                    count,
                    want_response,
                    will_sort: _,
                    sender_handle,
                    receiver_handle,
                } = &message;
                if self.them.reconciliation_announce_entries.is_some() {
                    return Err(Error::InvalidMessageInCurrentState);
                }
                let namespace =
                    self.range_is_authorised(&range, &receiver_handle, &sender_handle)?;
                if *count == 0 && !want_response {
                    // todo: what do we need to do here?
                    self.done = true;
                } else {
                    self.them.reconciliation_announce_entries = Some(message.clone());
                }
                if *want_response {
                    self.announce_entries(
                        store,
                        namespace,
                        range,
                        *receiver_handle,
                        *sender_handle,
                        false,
                    )?;
                }
            }
            Message::ReconciliationSendEntry(message) => {
                let state = self
                    .them
                    .reconciliation_announce_entries
                    .as_mut()
                    .ok_or(Error::InvalidMessageInCurrentState)?;
                let ReconciliationSendEntry {
                    entry,
                    static_token_handle,
                    dynamic_token,
                } = message;
                let static_token = self.them.static_tokens.try_get(&static_token_handle)?;
                // TODO: avoid clone
                let authorisation_token =
                    AuthorisationToken::from_parts(static_token.clone(), dynamic_token);
                let authorised_entry =
                    AuthorisedEntry::try_from_parts(entry.entry, authorisation_token)?;
                store.ingest_entry(&authorised_entry)?;

                state.count -= 1;
                if state.count == 0 {
                    self.them.reconciliation_announce_entries = None;
                }
            }
            _ => return Err(Error::UnsupportedMessage),
        }
        Ok(())
    }

    fn range_is_authorised(
        &self,
        range: &ThreeDRange,
        receiver_handle: &AreaOfInterestHandle,
        sender_handle: &AreaOfInterestHandle,
    ) -> Result<NamespaceId, Error> {
        let our_namespace = self.handle_to_namespace_id(Scope::Us, receiver_handle)?;
        let their_namespace = self.handle_to_namespace_id(Scope::Them, sender_handle)?;
        if our_namespace != their_namespace {
            return Err(Error::AreaOfInterestNamespaceMismatch);
        }
        let our_aoi = self.handle_to_aoi(Scope::Us, receiver_handle)?;
        let their_aoi = self.handle_to_aoi(Scope::Them, sender_handle)?;

        if !our_aoi.area().includes_range(&range) || !their_aoi.area().includes_range(&range) {
            return Err(Error::RangeOutsideCapability);
        }
        Ok(our_namespace.into())
    }

    fn handle_to_aoi(
        &self,
        scope: Scope,
        handle: &AreaOfInterestHandle,
    ) -> Result<&SetupBindAreaOfInterest, Error> {
        match scope {
            Scope::Us => self.us.areas_of_interest.try_get(handle),
            Scope::Them => self.them.areas_of_interest.try_get(handle),
        }
    }

    fn handle_to_namespace_id(
        &self,
        scope: Scope,
        handle: &AreaOfInterestHandle,
    ) -> Result<&NamespacePublicKey, Error> {
        let aoi = self.handle_to_aoi(scope, handle)?;
        let capability = match scope {
            Scope::Us => self.us.capabilities.try_get(&aoi.authorisation)?,
            Scope::Them => self.them.capabilities.try_get(&aoi.authorisation)?,
        };
        Ok(capability.granted_namespace())
    }
}

#[derive(Copy, Clone, Debug)]
enum Scope {
    Us,
    Them,
}

#[derive(Debug)]
pub struct Channel<T> {
    inbox: VecDeque<T>,
    outbox: VecDeque<T>,
    // issued_guarantees: usize,
}
impl<T: fmt::Debug> Default for Channel<T> {
    fn default() -> Self {
        Self::with_capacity(1024)
    }
}

impl<T: fmt::Debug> Channel<T> {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inbox: VecDeque::with_capacity(cap),
            outbox: VecDeque::with_capacity(cap),
        }
    }

    pub fn send(&mut self, value: impl Into<T>) -> bool {
        self.outbox.push_back(value.into());
        self.has_inbox_capacity()
    }

    fn outbox_drain(&mut self) -> impl Iterator<Item = T> + '_ {
        self.outbox.drain(..)
    }

    // fn inbox_drain(&mut self) -> impl Iterator<Item = T> + '_ {
    //     self.inbox.drain(..)
    // }

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
        self.inbox.capacity() - self.inbox.len()
    }

    pub fn has_inbox_capacity(&self) -> bool {
        self.remaining_inbox_capacity() > 0
    }

    // pub fn issuable_guarantees(&self) -> usize {
    //     self.remaining_capacity() - self.issued_guarantees
    // }
    //
    // pub fn offer_guarantees(&mut self) -> usize {
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
