use std::{
    collections::{hash_map, HashMap, HashSet, VecDeque},
    fmt,
};

use anyhow::bail;
use ed25519_dalek::SignatureError;
use futures::future::BoxFuture;
use genawaiter::{sync::Gen, GeneratorState};
use iroh_base::hash::Hash;
use tracing::{debug, info, trace, warn};

use crate::{
    proto::{
        grouping::{Area, AreaOfInterest, ThreeDRange},
        keys::{NamespaceId, NamespacePublicKey, UserSecretKey, UserSignature},
        meadowcap::{is_authorised_write, InvalidCapability},
        wgps::{
            AccessChallenge, AreaOfInterestHandle, CapabilityHandle, ChallengeHash,
            CommitmentReveal, ControlAbsolve, ControlAnnounceDropping, ControlApologise,
            ControlFreeHandle, ControlIssueGuarantee, ControlPlead, Fingerprint, Handle,
            HandleType, IntersectionHandle, LengthyEntry, LogicalChannel, Message, ReadCapability,
            ReconciliationAnnounceEntries, ReconciliationSendEntry, ReconciliationSendFingerprint,
            SetupBindAreaOfInterest, SetupBindReadCapability, SetupBindStaticToken, StaticToken,
            StaticTokenHandle, CHALLENGE_HASH_LENGTH,
        },
        willow::{
            AuthorisationToken, AuthorisedEntry, Entry, PossiblyAuthorisedEntry, Unauthorised,
        },
    },
    store::{RangeSplit, SplitAction, Store, SyncConfig},
};

const LOGICAL_CHANNEL_CAP: usize = 128;

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
    #[error("the received nonce does not match the received committment")]
    BrokenCommittement,
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
pub struct Resources {
    capabilities: ResourceMap<CapabilityHandle, ReadCapability>,
    areas_of_interest: ResourceMap<AreaOfInterestHandle, SetupBindAreaOfInterest>,
    static_tokens: ResourceMap<StaticTokenHandle, StaticToken>,
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
pub struct Session {
    role: Role,
    our_nonce: AccessChallenge,
    received_commitment: ChallengeHash,
    init: Option<SessionInit>,
    challenge: Option<Challenges>,
    // init_state: SessionInit,
    their_maximum_payload_size: usize,

    control_channel: Channel<Message>,
    reconciliation_channel: Channel<Message>,

    our_current_aoi: Option<AreaOfInterestHandle>,

    our_resources: Resources,
    their_resources: Resources,
    pending_ranges: HashSet<(AreaOfInterestHandle, ThreeDRange)>,
    pending_entries: Option<u64>,
    reconciliation_started: bool,
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
            role: our_role,
            our_nonce,
            challenge: None,
            their_maximum_payload_size,
            received_commitment,
            control_channel: Default::default(),
            reconciliation_channel: Default::default(),
            our_resources: Default::default(),
            their_resources: Default::default(),
            our_current_aoi: None, // config
            init: Some(init),
            pending_ranges: Default::default(),
            pending_entries: Default::default(),
            reconciliation_started: false,
        };
        let msg = CommitmentReveal { nonce: our_nonce };
        this.control_channel.send(msg);
        this
    }

    pub fn drain_outbox(&mut self) -> impl Iterator<Item = Message> + '_ {
        self.control_channel
            .outbox_drain()
            .chain(self.reconciliation_channel.outbox_drain())
    }

    pub fn our_role(&self) -> Role {
        self.role
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
        trace!(pending = self.pending_ranges.len(), "process start!");
        // always process control messages first
        while let Some(message) = self.control_channel.inbox_pop() {
            self.process_control(store, message)?;
        }
        while let Some(message) = self.reconciliation_channel.inbox_pop() {
            self.process_reconciliation(store, message)?;
        }
        trace!(pending = self.pending_ranges.len(), "process done!");
        Ok(self.reconciliation_started
            && self.pending_ranges.is_empty()
            && self.pending_entries.is_none())
    }

    fn init(&mut self, init: &SessionInit) -> Result<(), Error> {
        let area_of_interest = init.area_of_interest.clone();
        let capability = init.capability.clone();

        debug!(?init, "init");
        if *capability.receiver() != init.user_secret_key.public_key() {
            return Err(Error::WrongSecretKeyForCapability);
        }

        // TODO: implement private area intersection
        let intersection_handle = 0.into();

        // register read capability
        let signature = self.sign_challenge(&init.user_secret_key)?;
        let our_capability_handle = self.our_resources.capabilities.bind(capability.clone());
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
        let our_aoi_handle = self.our_resources.areas_of_interest.bind(msg.clone());
        self.control_channel.send(msg);
        self.our_current_aoi = Some(our_aoi_handle);

        Ok(())
    }

    fn sign_challenge(&self, secret_key: &UserSecretKey) -> Result<UserSignature, Error> {
        let challenge = self
            .challenge
            .as_ref()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        let signature = secret_key.sign(&challenge.ours);
        Ok(signature)
    }

    fn process_control<S: Store>(&mut self, store: &mut S, message: Message) -> Result<(), Error> {
        match message {
            Message::CommitmentReveal(msg) => {
                if self.challenge.is_some() {
                    return Err(Error::InvalidMessageInCurrentState);
                }
                if Hash::new(&msg.nonce).as_bytes() != &self.received_commitment {
                    return Err(Error::BrokenCommittement);
                }
                self.challenge = Some(Challenges::from_nonces(
                    self.role,
                    self.our_nonce,
                    msg.nonce,
                ));
                let init = self.init.take().expect("unreachable");
                self.init(&init)?;
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
                self.their_resources.capabilities.bind(msg.capability);
            }
            Message::SetupBindStaticToken(msg) => {
                self.their_resources.static_tokens.bind(msg.static_token);
            }
            Message::SetupBindAreaOfInterest(msg) => {
                let capability = self
                    .their_resources
                    .capabilities
                    .try_get(&msg.authorisation)?;
                capability.try_granted_area(&msg.area_of_interest.area)?;
                let their_handle = self.their_resources.areas_of_interest.bind(msg);

                if self.role == Role::Alfie {
                    if let Some(our_handle) = self.our_current_aoi.clone() {
                        self.init_reconciliation(store, &our_handle, &their_handle)?;
                    } else {
                        warn!(
                            "received area of interest from remote, but no area of interest set on our side"
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

    fn bind_static_token(&mut self, static_token: StaticToken) -> StaticTokenHandle {
        let (handle, is_new) = self
            .our_resources
            .static_tokens
            .bind_if_new(static_token.clone());
        if is_new {
            let msg = SetupBindStaticToken { static_token };
            self.control_channel
                .send(Message::SetupBindStaticToken(msg));
        }
        handle
    }

    /// Uses the blocking [`Store`] and thus may only be called in the worker thread.
    fn init_reconciliation<S: Store>(
        &mut self,
        store: &mut S,
        our_handle: &AreaOfInterestHandle,
        their_handle: &AreaOfInterestHandle,
    ) -> Result<(), Error> {
        let our_aoi = self.our_resources.areas_of_interest.try_get(&our_handle)?;
        let their_aoi = self
            .our_resources
            .areas_of_interest
            .try_get(&their_handle)?;

        let our_capability = self
            .our_resources
            .capabilities
            .try_get(&our_aoi.authorisation)?;
        let namespace = our_capability.granted_namespace();

        // TODO: intersect with their_aoi first
        let common_aoi = &our_aoi
            .area()
            .intersection(&their_aoi.area())
            .ok_or(Error::AreaOfInterestDoesNotOverlap)?;

        let range = common_aoi.into_range();
        let fingerprint = store.range_fingerprint(namespace.into(), &range)?;
        self.send_fingerprint(range, fingerprint, *our_handle, *their_handle, None);
        self.reconciliation_started = true;
        Ok(())
    }

    fn send_fingerprint(
        &mut self,
        range: ThreeDRange,
        fingerprint: Fingerprint,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        is_final_reply_for_range: Option<ThreeDRange>,
    ) {
        self.pending_ranges.insert((our_handle, range.clone()));
        let msg = ReconciliationSendFingerprint {
            range,
            fingerprint,
            sender_handle: our_handle,
            receiver_handle: their_handle,
            is_final_reply_for_range,
        };
        self.reconciliation_channel.send(msg);
    }

    fn announce_empty(
        &mut self,
        range: ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        want_response: bool,
        is_final_reply_for_range: Option<ThreeDRange>,
    ) -> Result<(), Error> {
        if want_response {
            self.pending_ranges.insert((our_handle, range.clone()));
        }
        let msg = ReconciliationAnnounceEntries {
            range,
            count: 0,
            want_response,
            will_sort: false,
            sender_handle: our_handle,
            receiver_handle: their_handle,
            is_final_reply_for_range,
        };
        self.reconciliation_channel
            .send(Message::ReconciliationAnnounceEntries(msg));
        Ok(())
    }

    fn announce_then_send_entries<S: Store>(
        &mut self,
        store: &mut S,
        namespace: NamespaceId,
        range: &ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        want_response: bool,
        is_final_reply_for_range: Option<ThreeDRange>,
        local_count: Option<u64>,
    ) -> Result<(), Error> {
        if want_response {
            self.pending_ranges.insert((our_handle, range.clone()));
        }
        let local_count = match local_count {
            Some(count) => count,
            None => store.count_range(namespace, &range)?,
        };
        let msg = ReconciliationAnnounceEntries {
            range: range.clone(),
            count: local_count,
            want_response,
            will_sort: false, // todo: sorted?
            sender_handle: our_handle,
            receiver_handle: their_handle,
            is_final_reply_for_range,
        };
        self.reconciliation_channel.send(msg);
        for authorised_entry in store.get_entries_with_authorisation(namespace, &range) {
            let authorised_entry = authorised_entry?;
            let (entry, token) = authorised_entry.into_parts();
            let (static_token, dynamic_token) = token.into_parts();
            // TODO: partial entries
            let available = entry.payload_length;
            let static_token_handle = self.bind_static_token(static_token);
            let msg = ReconciliationSendEntry {
                entry: LengthyEntry::new(entry, available),
                static_token_handle,
                dynamic_token,
            };
            self.reconciliation_channel.send(msg);
        }
        Ok(())
    }

    fn split_range_and_send_parts<S: Store>(
        &mut self,
        store: &mut S,
        namespace: NamespaceId,
        range: &ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
    ) -> Result<(), Error> {
        // TODO: expose this config
        let config = SyncConfig::default();
        let mut announce_entries = vec![];
        {
            let iter = store.split_range(namespace, &range, &config)?;
            let mut iter = iter.peekable();
            while let Some(res) = iter.next() {
                let (subrange, action) = res?;
                let is_last = iter.peek().is_none();
                let is_final_reply = is_last.then(|| range.clone());
                match action {
                    SplitAction::SendEntries(count) => {
                        announce_entries.push((subrange, count, is_final_reply));
                    }
                    SplitAction::SendFingerprint(fingerprint) => {
                        self.send_fingerprint(
                            subrange,
                            fingerprint,
                            our_handle,
                            their_handle,
                            is_final_reply,
                        );
                    }
                }
            }
        }
        // drop(iter);
        for (subrange, count, is_final_reply) in announce_entries.into_iter() {
            self.announce_then_send_entries(
                store,
                namespace,
                &subrange,
                our_handle,
                their_handle,
                true,
                is_final_reply,
                Some(count),
            )?;
        }
        Ok(())
    }

    fn clear_pending_range_if_some(
        &mut self,
        our_handle: AreaOfInterestHandle,
        pending_range: Option<ThreeDRange>,
    ) -> Result<(), Error> {
        if let Some(range) = pending_range {
            if !self.pending_ranges.remove(&(our_handle, range.clone())) {
                warn!("received duplicate final reply for range marker");
                return Err(Error::InvalidMessageInCurrentState);
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
                self.reconciliation_started = true;
                let ReconciliationSendFingerprint {
                    range,
                    fingerprint: their_fingerprint,
                    sender_handle: their_handle,
                    receiver_handle: our_handle,
                    is_final_reply_for_range,
                } = message;

                self.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;

                let namespace = self.range_is_authorised(&range, &our_handle, &their_handle)?;
                let our_fingerprint = store.range_fingerprint(namespace, &range)?;

                // case 1: fingerprint match.
                if our_fingerprint == their_fingerprint {
                    self.announce_empty(
                        range.clone(),
                        our_handle,
                        their_handle,
                        false,
                        Some(range.clone()),
                    )?;
                }
                // case 2: fingerprint is empty
                else if their_fingerprint.is_empty() {
                    self.announce_then_send_entries(
                        store,
                        namespace,
                        &range,
                        our_handle,
                        their_handle,
                        true,
                        Some(range.clone()),
                        None,
                    )?;
                }
                // case 3: fingerprint doesn't match and is non-empty
                else {
                    // reply by splitting the range into parts unless it is very short
                    self.split_range_and_send_parts(
                        store,
                        namespace,
                        &range,
                        our_handle,
                        their_handle,
                    )?;
                }
            }
            Message::ReconciliationAnnounceEntries(message) => {
                let ReconciliationAnnounceEntries {
                    range,
                    count,
                    want_response,
                    will_sort: _,
                    sender_handle: their_handle,
                    receiver_handle: our_handle,
                    is_final_reply_for_range,
                } = message;
                self.clear_pending_range_if_some(our_handle, is_final_reply_for_range)?;
                if self.pending_entries.is_some() {
                    return Err(Error::InvalidMessageInCurrentState);
                }
                let namespace = self.range_is_authorised(&range, &our_handle, &their_handle)?;
                if want_response {
                    self.announce_then_send_entries(
                        store,
                        namespace,
                        &range,
                        our_handle,
                        their_handle,
                        false,
                        Some(range.clone()),
                        None,
                    )?;
                }
                if count != 0 {
                    self.pending_entries = Some(count);
                }
            }
            Message::ReconciliationSendEntry(message) => {
                let remaining = self
                    .pending_entries
                    .as_mut()
                    .ok_or(Error::InvalidMessageInCurrentState)?;
                let ReconciliationSendEntry {
                    entry,
                    static_token_handle,
                    dynamic_token,
                } = message;
                let static_token = self
                    .their_resources
                    .static_tokens
                    .try_get(&static_token_handle)?;
                // TODO: avoid clone of static token?
                let authorisation_token =
                    AuthorisationToken::from_parts(static_token.clone(), dynamic_token);
                let authorised_entry =
                    AuthorisedEntry::try_from_parts(entry.entry, authorisation_token)?;
                store.ingest_entry(&authorised_entry)?;

                *remaining -= 1;
                if *remaining == 0 {
                    self.pending_entries = None;
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
            Scope::Us => self.our_resources.areas_of_interest.try_get(handle),
            Scope::Them => self.their_resources.areas_of_interest.try_get(handle),
        }
    }

    fn handle_to_namespace_id(
        &self,
        scope: Scope,
        handle: &AreaOfInterestHandle,
    ) -> Result<&NamespacePublicKey, Error> {
        let aoi = self.handle_to_aoi(scope, handle)?;
        let capability = match scope {
            Scope::Us => self
                .our_resources
                .capabilities
                .try_get(&aoi.authorisation)?,
            Scope::Them => self
                .their_resources
                .capabilities
                .try_get(&aoi.authorisation)?,
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
