use core::fmt;
use std::collections::{hash_map, HashMap, VecDeque};

use tracing::warn;

use crate::{
    proto::{
        keys::NamespaceId,
        meadowcap::is_authorised_write,
        wgps::{
            Area, Fingerprint, IntersectionHandle, LengthyEntry, StaticTokenHandle, ThreeDRange,
        },
        willow::{
            AuthorisationToken, AuthorisedEntry, Entry, PossiblyAuthorisedEntry, Unauthorised,
        },
    },
    store::{RangeSplitPart, Store},
};

use super::proto::wgps::{
    AreaOfInterest, AreaOfInterestHandle, CapabilityHandle, ControlAbsolve,
    ControlAnnounceDropping, ControlApologise, ControlFreeHandle, ControlIssueGuarantee,
    ControlPlead, ReadCapability, ReconciliationAnnounceEntries, ReconciliationSendEntry,
    ReconciliationSendFingerprint, SetupBindAreaOfInterest, SetupBindReadCapability,
    SetupBindStaticToken, StaticToken,
};

#[derive(Debug, derive_more::From, derive_more::TryInto)]
pub enum Message {
    Control(ControlMessage),
    Reconciliation(ReconciliationMessage),
}

#[derive(Debug, derive_more::From)]
pub enum ControlMessage {
    // TODO: move to CapabilityChannel
    SetupBindReadCapability(SetupBindReadCapability),
    // TODO: move to StaticTokenChannel
    SetupBindStaticToken(SetupBindStaticToken),
    // TODO: move to AreaOfInterestChannel
    SetupBindAreaOfInterest(SetupBindAreaOfInterest),
    // IssueGuarantee(ControlIssueGuarantee),
    // Absolve(ControlAbsolve),
    // Plead(ControlPlead),
    // AnnounceDropping(ControlAnnounceDropping),
    // Apologise(ControlApologise),
    FreeHandle(ControlFreeHandle),
}

#[derive(Debug, derive_more::From)]
pub enum ReconciliationMessage {
    SendFingerprint(ReconciliationSendFingerprint),
    AnnounceEntries(ReconciliationAnnounceEntries),
    SendEntry(ReconciliationSendEntry),
}

// struct HandleMap<H, R> {
//     next_handle: u64,
//     map: HashMap<R, H>,
// }
// impl<H, R> HandleMap<H, R>
// where
//     R: std::hash::Hash + Eq,
//     H: Handle,
// {
//     pub fn bind(&mut self, value: R) -> (H, bool) {
//         match self.map.entry(value) {
//             hash_map::Entry::Occupied(handle) => (*handle.get(), false),
//             hash_map::Entry::Vacant(entry) => {
//                 let handle: H = self.next_handle.into();
//                 self.next_handle += 1;
//                 entry.insert(handle);
//                 (handle, true)
//             }
//         }
//     }
// }

#[derive(Debug, Default)]
struct ResourceMap<H, R> {
    next_handle: u64,
    map: HashMap<H, Resource<R>>,
}

pub trait Handle: std::hash::Hash + From<u64> + Copy + Eq + PartialEq {}

impl Handle for CapabilityHandle {}
impl Handle for StaticTokenHandle {}
impl Handle for AreaOfInterestHandle {}

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
    #[error("missing resource")]
    MissingResource,
    #[error("missing resource")]
    RangeOutsideCapability,
    #[error("received a message that is not valid in the current session state")]
    InvalidMessageInCurrentState,
    #[error("our and their area of interests refer to different namespaces")]
    AreaOfInterestNamespaceMismatch,
    #[error("received an entry which is not authorised")]
    UnauthorisedEntryReceived,
}

impl From<Unauthorised> for Error {
    fn from(_value: Unauthorised) -> Self {
        Self::UnauthorisedEntryReceived
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

pub const CHALLENGE_LENGTH: usize = 32;
pub type Challenge = [u8; CHALLENGE_LENGTH];

#[derive(Debug)]
pub enum Role {
    Betty,
    Alfie,
}

#[derive(Debug)]
pub struct Session {
    our_role: Role,

    control_channel: Channel<ControlMessage>,
    reconciliation_channel: Channel<ReconciliationMessage>,

    us: PeerState,
    them: PeerState,
}

#[derive(Debug, PartialEq, Eq)]
struct BoundAreaOfInterest {
    area_of_interest: AreaOfInterest,
    authorisation: CapabilityHandle,
    namespace: NamespaceId,
}

impl BoundAreaOfInterest {
    pub fn includes_range(&self, range: &ThreeDRange) -> bool {
        self.area_of_interest.area.includes_range(range)
    }
}

#[derive(Debug)]
pub struct PeerState {
    challenge: Challenge,
    capabilities: ResourceMap<CapabilityHandle, ReadCapability>,
    areas_of_interest: ResourceMap<AreaOfInterestHandle, BoundAreaOfInterest>,
    static_tokens: ResourceMap<StaticTokenHandle, StaticToken>,
    reconciliation_announce_entries: Option<ReconciliationAnnounceEntries>, // intersections: ResourceMap<IntersectionHandle, intersections>,
}

impl Session {
    pub fn recv(&mut self, message: Message) {
        match message {
            Message::Control(msg) => self.control_channel.inbox_push_or_drop(msg),
            Message::Reconciliation(msg) => self.reconciliation_channel.inbox_push_or_drop(msg),
        }
    }

    pub fn pop_send(&mut self) -> Option<Message> {
        if let Some(message) = self.control_channel.outbox.pop_front() {
            return Some(message.into());
        };
        if let Some(message) = self.reconciliation_channel.outbox.pop_front() {
            return Some(message.into());
        };
        None
    }

    pub fn process<S: Store>(&mut self, store: &mut S) {
        while let Some(message) = self.control_channel.inbox_pop() {
            self.process_control(message).ok();
        }
        while let Some(message) = self.reconciliation_channel.inbox_pop() {
            self.process_reconciliation(message, store).ok();
        }
    }

    pub fn process_control(&mut self, message: ControlMessage) -> anyhow::Result<()> {
        match message {
            ControlMessage::SetupBindReadCapability(msg) => {
                msg.capability.validate()?;
                msg.capability
                    .receiver()
                    .verify(&self.us.challenge, &msg.signature)?;
                // todo: validate intersection handle
                self.them.capabilities.bind(msg.capability);
            }
            ControlMessage::SetupBindStaticToken(msg) => {
                self.them.static_tokens.bind(msg.static_token);
            }
            ControlMessage::SetupBindAreaOfInterest(msg) => {
                let capability = self.them.capabilities.try_get(&msg.authorisation)?;
                capability.try_granted_area(&msg.area_of_interest.area)?;
                let bound_aoi = BoundAreaOfInterest {
                    area_of_interest: msg.area_of_interest,
                    authorisation: msg.authorisation,
                    namespace: capability.granted_namespace().into(),
                };
                // let namespace = capability.granted_namespace();
                self.them.areas_of_interest.bind(bound_aoi);
            }
            ControlMessage::FreeHandle(_msg) => {
                // TODO: Free handles
            }
        }
        Ok(())
    }

    pub fn bind_static_token(&mut self, static_token: StaticToken) -> StaticTokenHandle {
        let (handle, is_new) = self.us.static_tokens.bind_if_new(static_token.clone());
        if is_new {
            let msg = SetupBindStaticToken { static_token };
            self.control_channel
                .send(ControlMessage::SetupBindStaticToken(msg));
        }
        handle
    }

    /// Uses the blocking [`Store`] and thus may only be called in the worker thread.
    pub fn process_reconciliation<S: Store>(
        &mut self,
        message: ReconciliationMessage,
        store: &mut S,
    ) -> Result<(), Error> {
        match message {
            ReconciliationMessage::SendFingerprint(msg) => {
                let ReconciliationSendFingerprint {
                    range,
                    fingerprint,
                    sender_handle,
                    receiver_handle,
                } = msg;

                let namespace = self.authorise_range(&range, &receiver_handle, &sender_handle)?;
                let our_fingerprint = store.get_fingerprint(namespace, &range)?;

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
                        .send(ReconciliationMessage::AnnounceEntries(msg));
                } else {
                    for part in store.split_range(namespace, &range)?.into_iter() {
                        match part {
                            RangeSplitPart::SendFingerprint(range, fingerprint) => {
                                let msg = ReconciliationSendFingerprint {
                                    range,
                                    fingerprint,
                                    sender_handle,
                                    receiver_handle,
                                };
                                self.reconciliation_channel
                                    .send(ReconciliationMessage::SendFingerprint(msg));
                            }
                            RangeSplitPart::SendEntries(range, local_count) => {
                                let msg = ReconciliationAnnounceEntries {
                                    range: range.clone(),
                                    count: local_count,
                                    want_response: true,
                                    will_sort: false, // todo: sorted?
                                    sender_handle,
                                    receiver_handle,
                                };
                                self.reconciliation_channel.send(msg.into());
                                for authorised_entry in
                                    store.get_entries_with_authorisation(namespace, &range)
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
                                    self.reconciliation_channel.send(msg.into());
                                }
                            }
                        }
                    }
                }
            }
            ReconciliationMessage::AnnounceEntries(msg) => {
                if self.them.reconciliation_announce_entries.is_some() {
                    return Err(Error::InvalidMessageInCurrentState);
                }
                self.authorise_range(&msg.range, &msg.receiver_handle, &msg.sender_handle)?;
                if msg.count == 0 {
                    // todo: what do we need to do here?
                } else {
                    self.them.reconciliation_announce_entries = Some(msg)
                }
            }
            ReconciliationMessage::SendEntry(msg) => {
                let state = self
                    .them
                    .reconciliation_announce_entries
                    .as_mut()
                    .ok_or(Error::InvalidMessageInCurrentState)?;
                let ReconciliationSendEntry {
                    entry,
                    static_token_handle,
                    dynamic_token,
                } = msg;
                let static_token = self.them.static_tokens.try_get(&static_token_handle)?;
                // TODO: omit clone of static token?
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
        }
        Ok(())
    }

    fn authorise_range(
        &self,
        range: &ThreeDRange,
        receiver_handle: &AreaOfInterestHandle,
        sender_handle: &AreaOfInterestHandle,
    ) -> Result<NamespaceId, Error> {
        let ours = self.us.areas_of_interest.try_get(&receiver_handle)?;
        let theirs = self.them.areas_of_interest.try_get(&sender_handle)?;
        if !ours.includes_range(&range) || !theirs.includes_range(&range) {
            return Err(Error::RangeOutsideCapability);
        };
        if ours.namespace != theirs.namespace {
            return Err(Error::AreaOfInterestNamespaceMismatch);
        }
        Ok(ours.namespace)
    }
}
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

impl<T: fmt::Debug> Channel<T> {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inbox: VecDeque::with_capacity(cap),
            outbox: VecDeque::with_capacity(cap),
        }
    }

    pub fn send(&mut self, value: T) -> bool {
        self.outbox.push_back(value);
        self.has_capacity()
    }

    pub fn inbox_pop(&mut self) -> Option<T> {
        self.inbox.pop_front()
    }

    pub fn inbox_push_or_drop(&mut self, message: T) {
        if let Some(dropped) = self.inbox_push(message) {
            warn!(message=?dropped, "dropping message");
        }
    }
    pub fn inbox_push(&mut self, message: T) -> Option<T> {
        if self.has_capacity() {
            self.inbox.push_back(message);
            None
        } else {
            Some(message)
        }
    }
    pub fn remaining_capacity(&self) -> usize {
        self.inbox.capacity() - self.inbox.len()
    }

    pub fn has_capacity(&self) -> bool {
        self.remaining_capacity() > 0
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
