use std::{cmp::Ordering, fmt};

use bytes::Bytes;
use ed25519_dalek::Signature;
use iroh_base::hash::Hash;
use iroh_net::key::PublicKey;
use serde::{Deserialize, Serialize};

use super::{
    grouping::{Area, AreaOfInterest, SubspaceArea, ThreeDRange},
    keys, meadowcap,
    willow::{
        AuthorisationToken, AuthorisedEntry, Entry, Path, PossiblyAuthorisedEntry, SubspaceId,
        Timestamp, Unauthorised, DIGEST_LENGTH,
    },
};

pub const MAX_PAYLOAD_SIZE_POWER: u8 = 12;

/// The maximum payload size limits when the other peer may include Payloads directly when transmitting Entries:
/// when an Entry’s payload_length is strictly greater than the maximum payload size,
/// its Payload may only be transmitted when explicitly requested.
///
/// The value is 4096.
pub const MAX_PAYLOAD_SIZE: usize = 2usize.pow(MAX_PAYLOAD_SIZE_POWER as u32);

pub const CHALLENGE_LENGTH: usize = 32;
pub const CHALLENGE_HASH_LENGTH: usize = DIGEST_LENGTH;
pub type ChallengeHash = [u8; CHALLENGE_HASH_LENGTH];
pub type AccessChallenge = [u8; CHALLENGE_LENGTH];

// In Meadowcap, for example, StaticToken is the type McCapability
// and DynamicToken is the type UserSignature,
// which together yield a MeadowcapAuthorisationToken.

pub type StaticToken = meadowcap::McCapability;
pub type DynamicToken = meadowcap::UserSignature;

/// Whereas write access control is baked into the Willow data model,
/// read access control resides in the replication layer.
/// To manage read access via capabilities, all peers must cooperate in sending Entries only to peers
/// who have presented a valid read capability for the Entry.
/// We describe the details in a capability-system-agnostic way here.
/// To use Meadowcap for this approach, simply choose the type of valid McCapabilities with access mode read as the read capabilities.
pub type ReadCapability = meadowcap::McCapability;
pub type SyncSignature = meadowcap::UserSignature;
pub type Receiver = meadowcap::UserPublicKey;

/// The different resource handles employed by the WGPS.
#[derive(Debug, Serialize, Deserialize)]
pub enum HandleType {
    /// Resource handle for the private set intersection part of private area intersection.
    /// More precisely, an IntersectionHandle stores a PsiGroup member together with one of two possible states:
    /// * pending (waiting for the other peer to perform scalar multiplication),
    /// * completed (both peers performed scalar multiplication).
    IntersectionHandle,

    /// Resource handle for [`ReadCapability`] that certify access to some Entries.
    CapabilityHandle,

    /// Resource handle for [`AreaOfInterest`]s that peers wish to sync.
    AreaOfInterestHandle,

    /// Resource handle that controls the matching from Payload transmissions to Payload requests.
    PayloadRequestHandle,

    /// Resource handle for [`StaticToken`]s that peers need to transmit.
    StaticTokenHandle,
}

/// The different logical channels employed by the WGPS.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogicalChannel {
    /// Control channel
    ControlChannel,
    /// Logical channel for performing 3d range-based set reconciliation.
    ReconciliationChannel,
    // TODO: use all the channels
    // right now everything but reconciliation goes into the control channel
    //
    // /// Logical channel for transmitting Entries and Payloads outside of 3d range-based set reconciliation.
    // DataChannel,
    //
    // /// Logical channel for controlling the binding of new IntersectionHandles.
    // IntersectionChannel,
    //
    // /// Logical channel for controlling the binding of new CapabilityHandles.
    // CapabilityChannel,
    //
    // /// Logical channel for controlling the binding of new AreaOfInterestHandles.
    // AreaOfInterestChannel,
    //
    // /// Logical channel for controlling the binding of new PayloadRequestHandles.
    // PayloadRequestChannel,
    //
    // /// Logical channel for controlling the binding of new StaticTokenHandles.
    // StaticTokenChannel,
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct AreaOfInterestHandle(u64);

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct IntersectionHandle(u64);

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct CapabilityHandle(u64);

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct StaticTokenHandle(u64);

pub trait Handle: std::hash::Hash + From<u64> + Copy + Eq + PartialEq {
    fn handle_type(&self) -> HandleType;
}

impl Handle for CapabilityHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::CapabilityHandle
    }
}
impl Handle for StaticTokenHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::StaticTokenHandle
    }
}
impl Handle for AreaOfInterestHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::AreaOfInterestHandle
    }
}
impl Handle for IntersectionHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::IntersectionHandle
    }
}

/// Complete the commitment scheme to determine the challenge for read authentication.
#[derive(Serialize, Deserialize, PartialEq, Eq, derive_more::Debug)]
pub struct CommitmentReveal {
    /// The nonce of the sender, encoded as a big-endian unsigned integer.
    #[debug("{}..", iroh_base::base32::fmt_short(self.nonce))]
    pub nonce: AccessChallenge,
}

#[derive(Serialize, Deserialize, derive_more::From, derive_more::Debug, strum::Display)]
pub enum Message {
    #[debug("{:?}", _0)]
    CommitmentReveal(CommitmentReveal),
    // PaiReplyFragment
    // PaiBindFragment
    // PaiRequestSubspaceCapability
    // PaiReplySubspaceCapability
    #[debug("{:?}", _0)]
    SetupBindStaticToken(SetupBindStaticToken),
    #[debug("{:?}", _0)]
    SetupBindReadCapability(SetupBindReadCapability),
    #[debug("{:?}", _0)]
    SetupBindAreaOfInterest(SetupBindAreaOfInterest),
    #[debug("{:?}", _0)]
    ReconciliationSendFingerprint(ReconciliationSendFingerprint),
    #[debug("{:?}", _0)]
    ReconciliationAnnounceEntries(ReconciliationAnnounceEntries),
    #[debug("{:?}", _0)]
    ReconciliationSendEntry(ReconciliationSendEntry),
    // DataSendEntry
    // DataSendPayload
    // DataSetMetadata
    // DataBindPayloadRequest
    // DataReplyPayload
    #[debug("{:?}", _0)]
    ControlIssueGuarantee(ControlIssueGuarantee),
    #[debug("{:?}", _0)]
    ControlAbsolve(ControlAbsolve),
    #[debug("{:?}", _0)]
    ControlPlead(ControlPlead),
    #[debug("{:?}", _0)]
    ControlAnnounceDropping(ControlAnnounceDropping),
    #[debug("{:?}", _0)]
    ControlApologise(ControlApologise),
    #[debug("{:?}", _0)]
    ControlFreeHandle(ControlFreeHandle),
}

impl Message {
    pub fn logical_channel(&self) -> LogicalChannel {
        match self {
            Message::ReconciliationSendFingerprint(_)
            | Message::ReconciliationAnnounceEntries(_)
            | Message::ReconciliationSendEntry(_) => LogicalChannel::ReconciliationChannel,
            _ => LogicalChannel::ControlChannel,
        }
    }
}

/// Bind a ReadCapability to a CapabilityHandle.
///
/// The SetupBindReadCapability messages let peers bind a ReadCapability for later reference.
/// To do so, they must present a valid SyncSignature over their challenge, thus demonstrating
/// they hold the secret key corresponding to receiver of the ReadCapability.
///
/// These requirements allow us to encode SetupBindReadCapability messages more efficiently.
/// The handle must be bound to the fragment (primary, if possible) of the capability with the
/// longest Path prefix that is in the intersection of the two peers’ fragments.
///
/// SetupBindReadCapability messages use the CapabilityChannel.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetupBindReadCapability {
    /// A ReadCapability that the peer wishes to reference in future messages.
    pub capability: ReadCapability,

    /// The IntersectionHandle, bound by the sender, of the capability’s fragment
    /// with the longest Path in the intersection of the fragments.
    ///
    /// If both a primary and secondary such fragment exist, choose the primary one.
    pub handle: IntersectionHandle,

    /// The SyncSignature issued by the Receiver of the capability over the sender’s challenge.
    pub signature: SyncSignature,
}

/// Bind an AreaOfInterest to an AreaOfInterestHandle.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct SetupBindAreaOfInterest {
    /// An AreaOfInterest that the peer wishes to reference in future messages.
    pub area_of_interest: AreaOfInterest,
    /// A CapabilityHandle bound by the sender that grants access to all entries in the message’s area_of_interest.
    pub authorisation: CapabilityHandle,
}

impl SetupBindAreaOfInterest {
    pub fn area(&self) -> &Area {
        &self.area_of_interest.area
    }
}

/// Bind a StaticToken to a StaticTokenHandle.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetupBindStaticToken {
    /// The StaticToken to bind.
    pub static_token: StaticToken,
}

/// Send a Fingerprint as part of 3d range-based set reconciliation.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReconciliationSendFingerprint {
    /// The 3dRange whose Fingerprint is transmitted.
    pub range: ThreeDRange,
    /// The Fingerprint of the range, that is, of all LengthyEntries the peer has in the range.
    pub fingerprint: Fingerprint,
    /// An AreaOfInterestHandle, bound by the sender of this message, that fully contains the range.
    pub sender_handle: AreaOfInterestHandle,
    /// An AreaOfInterestHandle, bound by the receiver of this message, that fully contains the range.
    pub receiver_handle: AreaOfInterestHandle,
    /// If this is this the last reply to range received via [`ReconciliationSendFingerprint`] or [`ReconciliationAnnounceEntries`]
    /// from the other peer, set to that range to indicate to the other peer that no further replies for that range will be sent
    ///
    /// TODO: This is a spec deviation, discuss further and remove or upstream
    pub is_final_reply_for_range: Option<ThreeDRange>,
}

/// Prepare transmission of the LengthyEntries a peer has in a 3dRange as part of 3d range-based set reconciliation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReconciliationAnnounceEntries {
    /// The 3dRange whose LengthyEntries to transmit.
    pub range: ThreeDRange,
    /// The number of Entries the sender has in the range.
    pub count: u64,
    /// A boolean flag to indicate whether the sender wishes to receive a ReconciliationAnnounceEntries message for the same 3dRange in return.
    pub want_response: bool,
    /// Whether the sender promises to send the Entries in the range sorted from oldest to newest.
    pub will_sort: bool,
    /// An AreaOfInterestHandle, bound by the sender of this message, that fully contains the range.
    pub sender_handle: AreaOfInterestHandle,
    /// An AreaOfInterestHandle, bound by the receiver of this message, that fully contains the range.
    pub receiver_handle: AreaOfInterestHandle,
    /// If this is this the last reply to range received via [`ReconciliationSendFingerprint`] or [`ReconciliationAnnounceEntries`]
    /// from the other peer, set to that range to indicate to the other peer that no further replies for that range will be sent
    /// 
    /// TODO: This is a spec deviation, discuss further and remove or upstream
    pub is_final_reply_for_range: Option<ThreeDRange>,
}

/// Transmit a LengthyEntry as part of 3d range-based set reconciliation.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReconciliationSendEntry {
    /// The LengthyEntry itself.
    pub entry: LengthyEntry,
    /// A StaticTokenHandle, bound by the sender of this message, that is bound to the static part of the entry’s AuthorisationToken.
    pub static_token_handle: StaticTokenHandle,
    /// The dynamic part of the entry’s AuthorisationToken.
    pub dynamic_token: DynamicToken,
}

impl ReconciliationSendEntry {
    pub fn into_authorised_entry(
        self,
        static_token: StaticToken,
    ) -> Result<AuthorisedEntry, Unauthorised> {
        let authorisation_token = AuthorisationToken::from_parts(static_token, self.dynamic_token);
        let entry = PossiblyAuthorisedEntry::new(self.entry.entry, authorisation_token);
        entry.authorise()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LengthyEntry {
    /// The Entry in question.
    pub entry: Entry,
    /// The number of consecutive bytes from the start of the entry’s Payload that the peer holds.
    pub available: u64,
}

impl LengthyEntry {
    pub fn new(entry: Entry, available: u64) -> Self {
        Self { entry, available }
    }
}

#[derive(Default, Serialize, Deserialize, Eq, PartialEq, Clone, Copy)]
pub struct Fingerprint(pub [u8; 32]);

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", iroh_base::base32::fmt_short(&self.0))
    }
}

impl Fingerprint {
    pub fn add_entry(&mut self, entry: &Entry) {
        let next = Fingerprint(*Hash::new(&entry.encode()).as_bytes());
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

/// Make a binding promise of available buffer capacity to the other peer
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlIssueGuarantee {
    pub amount: u64,
    pub channel: LogicalChannel,
}

/// Allow the other peer to reduce its total buffer capacity by amount.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlAbsolve {
    pub amount: u64,
    pub channel: LogicalChannel,
}

/// Ask the other peer to send an ControlAbsolve message
/// such that the receiver remaining guarantees will be target.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlPlead {
    pub target: u64,
    pub channel: LogicalChannel,
}

/// The server notifies the client that it has started dropping messages and will continue
/// to do so until it receives an Apologise message. The server must send any outstanding
/// guarantees of the logical channel before sending a AnnounceDropping message.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlAnnounceDropping {
    pub channel: LogicalChannel,
}

/// The client notifies the server that it can stop dropping messages on this logical channel.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlApologise {
    pub channel: LogicalChannel,
}

/// Ask the other peer to free a resource handle.
///
/// This is needed for symmetric protocols where peers act as both client and server simultaneously
/// and bind resource handles to the same handle types.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlFreeHandle {
    handle: u64,
    /// Indicates whether the peer sending this message is the one who created the handle (true) or not (false).
    mine: bool,
    handle_type: HandleType,
}
