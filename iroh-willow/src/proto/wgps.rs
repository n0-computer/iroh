use std::cmp::Ordering;

use bytes::Bytes;
use ed25519_dalek::Signature;
use iroh_base::hash::Hash;
use iroh_net::key::PublicKey;
use serde::{Deserialize, Serialize};

use super::{
    keys, meadowcap,
    willow::{
        AuthorisationToken, AuthorisedEntry, Entry, Path, PossiblyAuthorisedEntry, SubspaceId,
        Timestamp, Unauthorised, DIGEST_LENGTH,
    },
};

pub const MAXIMUM_PAYLOAD_SIZE_POWER: u8 = 12;
/// The maximum payload size limits when the other peer may include Payloads directly when transmitting Entries:
/// when an Entry’s payload_length is strictly greater than the maximum payload size,
/// its Payload may only be transmitted when explicitly requested.
///
/// The value is 4096.
pub const MAXIMUM_PAYLOAD_SIZE: usize = 2usize.pow(MAXIMUM_PAYLOAD_SIZE_POWER as u32);

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
    // TODO: actually use more channels
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

// skip: Private Area Intersection

/// A grouping of Entries that are among the newest in some store.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct AreaOfInterest {
    /// To be included in this AreaOfInterest, an Entry must be included in the area.
    pub area: Area,
    /// To be included in this AreaOfInterest, an Entry’s timestamp must be among the max_count greatest Timestamps, unless max_count is zero.
    pub max_count: u64,
    /// The total payload_lengths of all included Entries is at most max_size, unless max_size is zero.
    pub max_size: u64,
}

impl AreaOfInterest {
    pub fn full() -> Self {
        Self {
            area: Area::full(),
            max_count: 0,
            max_size: 0,
        }
    }
}

/// A grouping of Entries.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Area {
    /// To be included in this Area, an Entry’s subspace_id must be equal to the subspace_id, unless it is any.
    pub subspace_id: SubspaceArea,
    /// To be included in this Area, an Entry’s path must be prefixed by the path.
    pub path: Path,
    /// To be included in this Area, an Entry’s timestamp must be included in the times.
    pub times: Range<Timestamp>,
}

impl Area {
    pub const fn new(subspace_id: SubspaceArea, path: Path, times: Range<Timestamp>) -> Self {
        Self {
            subspace_id,
            path,
            times,
        }
    }

    pub fn full() -> Self {
        Self::new(SubspaceArea::Any, Path::empty(), Range::<Timestamp>::FULL)
    }

    pub fn empty() -> Self {
        Self::new(SubspaceArea::Any, Path::empty(), Range::<Timestamp>::EMPTY)
    }

    pub fn subspace(subspace_id: SubspaceId) -> Self {
        Self::new(
            SubspaceArea::Id(subspace_id),
            Path::empty(),
            Range::<Timestamp>::FULL,
        )
    }

    pub fn includes_entry(&self, entry: &Entry) -> bool {
        self.subspace_id.includes_subspace(&entry.subspace_id)
            && self.path.is_prefix_of(&entry.path)
            && self.times.includes(&entry.timestamp)
    }

    pub fn includes_area(&self, other: &Area) -> bool {
        self.subspace_id.includes(&other.subspace_id)
            && self.path.is_prefix_of(&other.path)
            && self.times.includes_range(&other.times)
    }

    pub fn includes_range(&self, range: &ThreeDRange) -> bool {
        let path_start = self.path.is_prefix_of(&range.paths.start);
        let path_end = match &range.paths.end {
            RangeEnd::Open => true,
            RangeEnd::Closed(path) => self.path.is_prefix_of(path),
        };
        let subspace_start = self.subspace_id.includes_subspace(&range.subspaces.start);
        let subspace_end = match range.subspaces.end {
            RangeEnd::Open => true,
            RangeEnd::Closed(subspace) => self.subspace_id.includes_subspace(&subspace),
        };
        subspace_start
            && subspace_end
            && path_start
            && path_end
            && self.times.includes_range(&range.times)
    }

    pub fn into_range(&self) -> ThreeDRange {
        let subspace_start = match self.subspace_id {
            SubspaceArea::Any => SubspaceId::zero(),
            SubspaceArea::Id(id) => id,
        };
        let subspace_end = match self.subspace_id {
            SubspaceArea::Any => RangeEnd::Open,
            SubspaceArea::Id(id) => subspace_range_end(id),
        };
        let path_start = self.path.clone();
        let path_end = path_range_end(&self.path);
        ThreeDRange {
            subspaces: Range::new(subspace_start, subspace_end),
            paths: Range::new(path_start, path_end),
            times: self.times.clone(),
        }
    }

    pub fn intersection(&self, other: &Area) -> Option<Area> {
        let subspace_id = self.subspace_id.intersection(&other.subspace_id)?;
        let path = self.path.intersection(&other.path)?;
        let times = self.times.intersection(&other.times)?;
        Some(Self {
            subspace_id,
            times,
            path,
        })
    }
}

fn path_range_end(path: &Path) -> RangeEnd<Path> {
    if path.is_empty() {
        RangeEnd::Open
    } else {
        let mut out = vec![];
        for component in path.iter().rev() {
            // component can be incremented
            if out.is_empty() && component.iter().any(|x| *x != 0xff) {
                let mut bytes = Vec::with_capacity(component.len());
                bytes.copy_from_slice(&component);
                let incremented = increment_by_one(&mut bytes);
                debug_assert!(incremented, "checked above");
                out.push(Bytes::from(bytes));
                break;
            // component cannot be incremented
            } else if out.is_empty() {
                continue;
            } else {
                out.push(component.clone())
            }
        }
        if out.is_empty() {
            RangeEnd::Open
        } else {
            out.reverse();
            RangeEnd::Closed(Path::from_bytes_unchecked(out))
        }
    }
    // let mut bytes = id.to_bytes();
    // if increment_by_one(&mut bytes) {
    //     RangeEnd::Closed(SubspaceId::from_bytes_unchecked(bytes))
    // } else {
    //     RangeEnd::Open
    // }
}

fn subspace_range_end(id: SubspaceId) -> RangeEnd<SubspaceId> {
    let mut bytes = id.to_bytes();
    if increment_by_one(&mut bytes) {
        RangeEnd::Closed(SubspaceId::from_bytes_unchecked(bytes))
    } else {
        RangeEnd::Open
    }
}

/// Increment a byte string by one, by incrementing the last byte that is not 255 by one.
///
/// Returns false if all bytes are 255.
fn increment_by_one(value: &mut [u8]) -> bool {
    for char in value.iter_mut().rev() {
        if *char != 255 {
            *char += 1;
            return true;
        } else {
            *char = 0;
        }
    }
    false
}

impl Range<Timestamp> {
    pub const FULL: Self = Self {
        start: 0,
        end: RangeEnd::Open,
    };

    pub const EMPTY: Self = Self {
        start: 0,
        end: RangeEnd::Closed(0),
    };

    fn intersection(&self, other: &Self) -> Option<Self> {
        let start = self.start.max(other.start);
        let end = match (&self.end, &other.end) {
            (RangeEnd::Open, RangeEnd::Closed(b)) => RangeEnd::Closed(*b),
            (RangeEnd::Closed(a), RangeEnd::Closed(b)) => RangeEnd::Closed(*a.min(b)),
            (RangeEnd::Closed(a), RangeEnd::Open) => RangeEnd::Closed(*a),
            (RangeEnd::Open, RangeEnd::Open) => RangeEnd::Open,
        };
        match end {
            RangeEnd::Open => Some(Self::new(start, end)),
            RangeEnd::Closed(t) if t >= start => Some(Self::new(start, end)),
            RangeEnd::Closed(_) => Some(Self::new(start, end)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum SubspaceArea {
    Any,
    Id(SubspaceId),
}

impl SubspaceArea {
    fn includes(&self, other: &SubspaceArea) -> bool {
        match (self, other) {
            (SubspaceArea::Any, SubspaceArea::Any) => true,
            (SubspaceArea::Id(_), SubspaceArea::Any) => false,
            (_, SubspaceArea::Id(id)) => self.includes_subspace(id),
        }
    }
    fn includes_subspace(&self, subspace_id: &SubspaceId) -> bool {
        match self {
            Self::Any => true,
            Self::Id(id) => id == subspace_id,
        }
    }

    fn intersection(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Any, Self::Any) => Some(Self::Any),
            (Self::Id(a), Self::Any) => Some(Self::Id(*a)),
            (Self::Any, Self::Id(b)) => Some(Self::Id(*b)),
            (Self::Id(a), Self::Id(b)) if a == b => Some(Self::Id(*a)),
            (Self::Id(_a), Self::Id(_b)) => None,
        }
    }
}

#[derive(Serialize, Deserialize, derive_more::From, derive_more::Debug)]
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

#[derive(Debug, Default, Serialize, Deserialize, Eq, PartialEq, Clone, Copy)]
pub struct Fingerprint(pub [u8; 32]);

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
}

impl std::ops::BitXorAssign for Fingerprint {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= b;
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreeDRange {
    pub paths: Range<Path>,
    pub subspaces: Range<SubspaceId>,
    pub times: Range<Timestamp>,
}

impl ThreeDRange {
    pub fn includes_entry(&self, entry: &Entry) -> bool {
        self.subspaces.includes(&entry.subspace_id)
            && self.paths.includes(&entry.path)
            && self.times.includes(&entry.timestamp)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Range<T> {
    pub start: T,
    pub end: RangeEnd<T>,
}

impl<T> Range<T> {
    pub fn new(start: T, end: RangeEnd<T>) -> Self {
        Self { start, end }
    }
    pub fn is_closed(&self) -> bool {
        matches!(self.end, RangeEnd::Closed(_))
    }
    pub fn is_open(&self) -> bool {
        matches!(self.end, RangeEnd::Open)
    }
}

impl<T: Ord + PartialOrd> Range<T> {
    pub fn includes(&self, value: &T) -> bool {
        value >= &self.start && self.end.includes(value)
    }

    pub fn includes_range(&self, other: &Range<T>) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum RangeEnd<T> {
    Closed(T),
    Open,
}

impl<T: Ord + PartialOrd> PartialOrd for RangeEnd<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (RangeEnd::Open, RangeEnd::Closed(_)) => Some(Ordering::Greater),
            (RangeEnd::Closed(_), RangeEnd::Open) => Some(Ordering::Less),
            (RangeEnd::Closed(a), RangeEnd::Closed(b)) => a.partial_cmp(b),
            (RangeEnd::Open, RangeEnd::Open) => Some(Ordering::Equal),
        }
    }
}

// impl<T: Ord + PartialOrd> PartialOrd<T> for RangeEnd<T> {
//     fn partial_cmp(&self, other: &T) -> Option<Ordering> {
//         // match (self, other) {
//         //     (RangeEnd::Open, RangeEnd::Closed(_)) => Some(Ordering::Greater),
//         //     (RangeEnd::Closed(_), RangeEnd::Open) => Some(Ordering::Less),
//         //     (RangeEnd::Closed(a), RangeEnd::Closed(b)) => a.partial_cmp(b),
//         //     (RangeEnd::Open, RangeEnd::Open) => Some(Ordering::Equal),
//         // }
//     }
// }

impl<T: Ord + PartialOrd> RangeEnd<T> {
    pub fn includes(&self, value: &T) -> bool {
        match self {
            Self::Open => true,
            Self::Closed(end) => value < end,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlMessage {}

/// Make a binding promise of available buffer capacity to the other peer
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlIssueGuarantee {
    amount: u64,
    channel: LogicalChannel,
}

/// Allow the other peer to reduce its total buffer capacity by amount.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlAbsolve {
    amount: u64,
    channel: LogicalChannel,
}

/// Ask the other peer to send an ControlAbsolve message
/// such that the receiver remaining guarantees will be target.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlPlead {
    target: u64,
    channel: LogicalChannel,
}

/// The server notifies the client that it has started dropping messages and will continue
/// to do so until it receives an Apologise message. The server must send any outstanding
/// guarantees of the logical channel before sending a AnnounceDropping message.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlAnnounceDropping {
    channel: LogicalChannel,
}

/// The client notifies the server that it can stop dropping messages on this logical channel.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlApologise {
    channel: LogicalChannel,
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
