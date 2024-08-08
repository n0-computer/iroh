use std::{fmt, io::Write, sync::Arc};

use iroh_base::{base32::fmt_short, hash::Hash};
use rand::Rng;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use strum::{EnumCount, VariantArray};

use crate::{
    proto::keys::UserSecretKey,
    util::codec::{DecodeOutcome, Decoder, Encoder},
};

use super::{
    grouping::{Area, AreaOfInterest, ThreeDRange},
    keys::{NamespaceSecretKey, UserPublicKey},
    meadowcap::{self, AccessMode},
    willow::{Entry, NamespaceId, DIGEST_LENGTH},
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

#[derive(derive_more::Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChallengeHash(#[debug("{}..", fmt_short(self.0))] [u8; CHALLENGE_HASH_LENGTH]);

impl ChallengeHash {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; CHALLENGE_HASH_LENGTH]) -> Self {
        Self(bytes)
    }
}

#[derive(derive_more::Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct AccessChallenge(#[debug("{}..", fmt_short(self.0))] AccessChallengeBytes);

pub type AccessChallengeBytes = [u8; CHALLENGE_LENGTH];

impl Default for AccessChallenge {
    fn default() -> Self {
        Self::generate()
    }
}

impl AccessChallenge {
    pub fn generate() -> Self {
        Self(rand::random())
    }

    pub fn generate_with_rng(rng: &mut impl CryptoRngCore) -> Self {
        Self(rng.gen())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn hash(&self) -> ChallengeHash {
        ChallengeHash(*Hash::new(self.0).as_bytes())
    }
}

// In Meadowcap, for example, StaticToken is the type McCapability
// and DynamicToken is the type UserSignature,
// which together yield a MeadowcapAuthorisationToken.

pub type StaticToken = meadowcap::McCapability;
pub type ValidatedStaticToken = meadowcap::ValidatedCapability;
pub type DynamicToken = meadowcap::UserSignature;

/// Whereas write access control is baked into the Willow data model,
/// read access control resides in the replication layer.
/// To manage read access via capabilities, all peers must cooperate in sending Entries only to peers
/// who have presented a valid read capability for the Entry.
/// We describe the details in a capability-system-agnostic way here.
/// To use Meadowcap for this approach, simply choose the type of valid McCapabilities with access mode read as the read capabilities.
pub type ReadCapability = meadowcap::McCapability;

/// Whenever a peer is granted a complete read capability of non-empty path,
/// it should also be granted a corresponding subspace capability.
/// Each subspace capability must have a single receiver (a public key of some signature scheme),
/// and a single granted namespace (a NamespaceId).
/// The receiver can authenticate itself by signing a collaboratively selected nonce.
pub type SubspaceCapability = Arc<meadowcap::McSubspaceCapability>;

pub type SyncSignature = meadowcap::UserSignature;

pub type Receiver = meadowcap::UserPublicKey;

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

/// Represents an authorisation to read an area of data in a Namespace.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct ReadAuthorisation(ReadCapability, Option<SubspaceCapability>);

impl ReadAuthorisation {
    pub fn new(read_cap: ReadCapability, subspace_cap: Option<SubspaceCapability>) -> Self {
        Self(read_cap, subspace_cap)
    }

    pub fn new_owned(namespace_secret: &NamespaceSecretKey, user_key: UserPublicKey) -> Self {
        let read_cap = ReadCapability::new_owned(namespace_secret, user_key, AccessMode::ReadOnly);
        let subspace_cap = Arc::new(meadowcap::McSubspaceCapability::new(
            namespace_secret,
            user_key,
        ));
        Self::new(read_cap, Some(subspace_cap))
    }

    pub fn read_cap(&self) -> &ReadCapability {
        &self.0
    }

    pub fn subspace_cap(&self) -> Option<&SubspaceCapability> {
        self.1.as_ref()
    }

    pub fn namespace(&self) -> NamespaceId {
        self.0.granted_namespace().id()
    }

    pub fn delegate(
        &self,
        user_secret: &UserSecretKey,
        new_user: UserPublicKey,
        new_area: Area,
    ) -> anyhow::Result<Self> {
        let subspace_cap = match self.subspace_cap() {
            Some(subspace_cap) if new_area.subspace.is_any() && !new_area.path.is_empty() => {
                Some(Arc::new(subspace_cap.delegate(user_secret, new_user)?))
            }
            _ => None,
        };
        let read_cap = self.read_cap().delegate(user_secret, new_user, new_area)?;
        Ok(Self::new(read_cap, subspace_cap))
    }
}

/// The different resource handles employed by the WGPS.
#[derive(Debug, Serialize, Deserialize, strum::Display)]
pub enum HandleType {
    /// Resource handle for the private set intersection part of private area intersection.
    /// More precisely, an IntersectionHandle stores a PsiGroup member together with one of two possible states:
    /// * pending (waiting for the other peer to perform scalar multiplication),
    /// * completed (both peers performed scalar multiplication).
    Intersection,

    /// Resource handle for [`ReadCapability`] that certify access to some Entries.
    Capability,

    /// Resource handle for [`AreaOfInterest`]s that peers wish to sync.
    AreaOfInterest,

    /// Resource handle that controls the matching from Payload transmissions to Payload requests.
    PayloadRequest,

    /// Resource handle for [`StaticToken`]s that peers need to transmit.
    StaticToken,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, derive_more::TryFrom)]
pub enum Channel {
    Control,
    Logical(LogicalChannel),
}

impl Channel {
    pub const COUNT: usize = LogicalChannel::COUNT + 1;

    pub fn all() -> [Channel; LogicalChannel::COUNT + 1] {
        // TODO: do this without allocation
        // https://users.rust-lang.org/t/how-to-concatenate-array-literals-in-compile-time/21141/3
        [Self::Control]
            .into_iter()
            .chain(LogicalChannel::VARIANTS.iter().copied().map(Self::Logical))
            .collect::<Vec<_>>()
            .try_into()
            .expect("static length")
    }

    pub fn fmt_short(&self) -> &'static str {
        match self {
            Channel::Control => "Ctl",
            Channel::Logical(ch) => ch.fmt_short(),
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            Channel::Control => 0,
            Channel::Logical(ch) => ch.id(),
        }
    }

    pub fn from_id(id: u8) -> Result<Self, InvalidChannelId> {
        match id {
            0 => Ok(Self::Control),
            _ => {
                let ch = LogicalChannel::from_id(id)?;
                Ok(Self::Logical(ch))
            }
        }
    }
}

/// The different logical channels employed by the WGPS.
#[derive(
    Debug,
    Serialize,
    Deserialize,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    strum::EnumIter,
    strum::VariantArray,
    strum::EnumCount,
)]
pub enum LogicalChannel {
    /// Logical channel for controlling the binding of new IntersectionHandles.
    Intersection,
    /// Logical channel for controlling the binding of new CapabilityHandles.
    Capability,
    /// Logical channel for controlling the binding of new AreaOfInterestHandles.
    AreaOfInterest,
    /// Logical channel for controlling the binding of new StaticTokenHandles.
    StaticToken,
    /// Logical channel for performing 3d range-based set reconciliation.
    Reconciliation,
    /// Logical channel for transmitting Entries and Payloads outside of 3d range-based set reconciliation.
    Data,
    // /// Logical channel for controlling the binding of new PayloadRequestHandles.
    // PayloadRequest,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid channel id")]
pub struct InvalidChannelId;

impl LogicalChannel {
    pub fn all() -> [LogicalChannel; LogicalChannel::COUNT] {
        LogicalChannel::VARIANTS
            .try_into()
            .expect("statically checked")
    }
    pub fn fmt_short(&self) -> &'static str {
        match self {
            LogicalChannel::Intersection => "Pai",
            LogicalChannel::Reconciliation => "Rec",
            LogicalChannel::StaticToken => "StT",
            LogicalChannel::Capability => "Cap",
            LogicalChannel::AreaOfInterest => "AoI",
            LogicalChannel::Data => "Dat",
        }
    }

    pub fn from_id(id: u8) -> Result<Self, InvalidChannelId> {
        match id {
            2 => Ok(Self::Intersection),
            3 => Ok(Self::AreaOfInterest),
            4 => Ok(Self::Capability),
            5 => Ok(Self::StaticToken),
            6 => Ok(Self::Reconciliation),
            7 => Ok(Self::Data),
            _ => Err(InvalidChannelId),
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            LogicalChannel::Intersection => 2,
            LogicalChannel::AreaOfInterest => 3,
            LogicalChannel::Capability => 4,
            LogicalChannel::StaticToken => 5,
            LogicalChannel::Reconciliation => 6,
            LogicalChannel::Data => 7,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct AreaOfInterestHandle(u64);

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct IntersectionHandle(u64);

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct CapabilityHandle(u64);

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct StaticTokenHandle(u64);

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub enum ResourceHandle {
    AreaOfInterest(AreaOfInterestHandle),
    Intersection(IntersectionHandle),
    Capability(CapabilityHandle),
    StaticToken(StaticTokenHandle),
}

pub trait IsHandle:
    std::fmt::Debug + std::hash::Hash + From<u64> + Into<ResourceHandle> + Copy + Eq + PartialEq
{
    fn handle_type(&self) -> HandleType;
    fn value(&self) -> u64;
}

impl IsHandle for CapabilityHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::Capability
    }
    fn value(&self) -> u64 {
        self.0
    }
}
impl IsHandle for StaticTokenHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::StaticToken
    }
    fn value(&self) -> u64 {
        self.0
    }
}
impl IsHandle for AreaOfInterestHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::AreaOfInterest
    }
    fn value(&self) -> u64 {
        self.0
    }
}
impl IsHandle for IntersectionHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::Intersection
    }
    fn value(&self) -> u64 {
        self.0
    }
}

/// Complete the commitment scheme to determine the challenge for read authentication.
#[derive(Serialize, Deserialize, PartialEq, Eq, derive_more::Debug)]
pub struct CommitmentReveal {
    /// The nonce of the sender, encoded as a big-endian unsigned integer.
    #[debug("{}..", iroh_base::base32::fmt_short(self.nonce.0))]
    pub nonce: AccessChallenge,
}

#[derive(
    Serialize,
    Deserialize,
    derive_more::From,
    derive_more::TryInto,
    derive_more::Debug,
    strum::Display,
)]
pub enum Message {
    #[debug("{:?}", _0)]
    CommitmentReveal(CommitmentReveal),
    #[debug("{:?}", _0)]
    PaiReplyFragment(PaiReplyFragment),
    #[debug("{:?}", _0)]
    PaiBindFragment(PaiBindFragment),
    #[debug("{:?}", _0)]
    PaiRequestSubspaceCapability(PaiRequestSubspaceCapability),
    #[debug("{:?}", _0)]
    PaiReplySubspaceCapability(Box<PaiReplySubspaceCapability>),
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
    #[debug("{:?}", _0)]
    ReconciliationSendPayload(ReconciliationSendPayload),
    #[debug("{:?}", _0)]
    ReconciliationTerminatePayload(ReconciliationTerminatePayload),
    #[debug("{:?}", _0)]
    DataSendEntry(DataSendEntry),
    #[debug("{:?}", _0)]
    DataSendPayload(DataSendPayload),
    #[debug("{:?}", _0)]
    DataSetMetadata(DataSetMetadata),
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
    pub fn same_kind(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    pub fn covers_region(&self) -> Option<(AreaOfInterestHandle, u64)> {
        match self {
            Message::ReconciliationSendFingerprint(msg) => {
                msg.covers.map(|covers| (msg.receiver_handle, covers))
            }
            Message::ReconciliationAnnounceEntries(msg) => {
                msg.covers.map(|covers| (msg.receiver_handle, covers))
            }
            _ => None,
        }
    }
}

impl Encoder for Message {
    fn encoded_len(&self) -> usize {
        let data_len = postcard::experimental::serialized_size(&self).unwrap();
        let header_len = 4;
        data_len + header_len
    }

    fn encode_into<W: Write>(&self, out: &mut W) -> anyhow::Result<()> {
        let len = postcard::experimental::serialized_size(&self).unwrap() as u32;
        out.write_all(&len.to_be_bytes())?;
        postcard::to_io(self, out)?;
        Ok(())
    }
}

impl Decoder for Message {
    fn decode_from(data: &[u8]) -> anyhow::Result<DecodeOutcome<Self>> {
        // tracing::debug!(input_len = data.len(), "Message decode: start");
        if data.len() < 4 {
            return Ok(DecodeOutcome::NeedMoreData);
        }
        let len = u32::from_be_bytes(data[..4].try_into().expect("just checked")) as usize;
        // tracing::debug!(msg_len = len, "Message decode: parsed len");
        let end = len + 4;
        if data.len() < end {
            // tracing::debug!("Message decode: need more data");
            return Ok(DecodeOutcome::NeedMoreData);
        }
        // tracing::debug!("Message decode: now deserilalize");
        let res = postcard::from_bytes(&data[4..end]);
        // tracing::debug!(?res, "Message decode: res");
        let item = res?;
        // tracing::debug!(?item, "Message decode: decoded!");
        Ok(DecodeOutcome::Decoded {
            item,
            consumed: end,
        })
    }
}

impl Message {
    pub fn channel(&self) -> Channel {
        match self {
            Message::PaiBindFragment(_) | Message::PaiReplyFragment(_) => {
                Channel::Logical(LogicalChannel::Intersection)
            }

            Message::SetupBindReadCapability(_) => Channel::Logical(LogicalChannel::Capability),
            Message::SetupBindAreaOfInterest(_) => Channel::Logical(LogicalChannel::AreaOfInterest),
            Message::SetupBindStaticToken(_) => Channel::Logical(LogicalChannel::StaticToken),

            Message::ReconciliationSendFingerprint(_)
            | Message::ReconciliationAnnounceEntries(_)
            | Message::ReconciliationSendEntry(_)
            | Message::ReconciliationSendPayload(_)
            | Message::ReconciliationTerminatePayload(_) => {
                Channel::Logical(LogicalChannel::Reconciliation)
            }

            Message::DataSendEntry(_)
            | Message::DataSendPayload(_)
            | Message::DataSetMetadata(_) => Channel::Logical(LogicalChannel::Data),

            Message::CommitmentReveal(_)
            | Message::PaiRequestSubspaceCapability(_)
            | Message::PaiReplySubspaceCapability(_)
            | Message::ControlIssueGuarantee(_)
            | Message::ControlAbsolve(_)
            | Message::ControlPlead(_)
            | Message::ControlAnnounceDropping(_)
            | Message::ControlApologise(_)
            | Message::ControlFreeHandle(_) => Channel::Control,
        }
    }
}

// #[derive(Debug, derive_more::From, derive_more::TryInto)]
// pub enum ChanMessage {
//     Control(ControlMessage),
//     Reconciliation(ReconciliationMessage),
// }
// impl From<Message> for ChanMessage {
//     fn from(value: Message) -> Self {
//         match value {
//             Message::ReconciliationSendFingerprint(msg) => Self::Reconciliation(msg.into()),
//             Message::ReconciliationAnnounceEntries(msg) => Self::Reconciliation(msg.into()),
//             Message::ReconciliationSendEntry(msg) => Self::Reconciliation(msg.into()),
//
//             Message::CommitmentReveal(msg) => Self::Control(msg.into()),
//             Message::SetupBindStaticToken(msg) => Self::Control(msg.into()),
//             Message::SetupBindReadCapability(msg) => Self::Control(msg.into()),
//             Message::SetupBindAreaOfInterest(msg) => Self::Control(msg.into()),
//
//             Message::ControlIssueGuarantee(msg) => Self::Control(msg.into()),
//             Message::ControlAbsolve(msg) => Self::Control(msg.into()),
//             Message::ControlPlead(msg) => Self::Control(msg.into()),
//             Message::ControlAnnounceDropping(msg) => Self::Control(msg.into()),
//             Message::ControlApologise(msg) => Self::Control(msg.into()),
//             Message::ControlFreeHandle(msg) => Self::Control(msg.into()),
//         }
//     }
// }
// impl From<ChanMessage> for Message {
//     fn from(message: ChanMessage) -> Self {
//         match message {
//             ChanMessage::Control(message) => message.into(),
//             ChanMessage::Reconciliation(message) => message.into(),
//         }
//     }
// }

#[derive(Debug, derive_more::From, strum::Display)]
pub enum ReconciliationMessage {
    SendFingerprint(ReconciliationSendFingerprint),
    AnnounceEntries(ReconciliationAnnounceEntries),
    SendEntry(ReconciliationSendEntry),
    SendPayload(ReconciliationSendPayload),
    TerminatePayload(ReconciliationTerminatePayload),
}

impl TryFrom<Message> for ReconciliationMessage {
    type Error = ();
    fn try_from(message: Message) -> Result<Self, Self::Error> {
        match message {
            Message::ReconciliationSendFingerprint(msg) => Ok(msg.into()),
            Message::ReconciliationAnnounceEntries(msg) => Ok(msg.into()),
            Message::ReconciliationSendEntry(msg) => Ok(msg.into()),
            Message::ReconciliationSendPayload(msg) => Ok(msg.into()),
            Message::ReconciliationTerminatePayload(msg) => Ok(msg.into()),
            _ => Err(()),
        }
    }
}

impl From<ReconciliationMessage> for Message {
    fn from(message: ReconciliationMessage) -> Self {
        match message {
            ReconciliationMessage::SendFingerprint(message) => message.into(),
            ReconciliationMessage::AnnounceEntries(message) => message.into(),
            ReconciliationMessage::SendEntry(message) => message.into(),
            ReconciliationMessage::SendPayload(message) => message.into(),
            ReconciliationMessage::TerminatePayload(message) => message.into(),
        }
    }
}

#[derive(Debug, derive_more::From, strum::Display)]
pub enum DataMessage {
    SendEntry(DataSendEntry),
    SendPayload(DataSendPayload),
    SetMetadata(DataSetMetadata),
}

impl TryFrom<Message> for DataMessage {
    type Error = ();
    fn try_from(message: Message) -> Result<Self, Self::Error> {
        match message {
            Message::DataSendEntry(msg) => Ok(msg.into()),
            Message::DataSendPayload(msg) => Ok(msg.into()),
            Message::DataSetMetadata(msg) => Ok(msg.into()),
            _ => Err(()),
        }
    }
}

impl From<DataMessage> for Message {
    fn from(message: DataMessage) -> Self {
        match message {
            DataMessage::SendEntry(message) => message.into(),
            DataMessage::SendPayload(message) => message.into(),
            DataMessage::SetMetadata(message) => message.into(),
        }
    }
}

#[derive(Debug, derive_more::From, strum::Display)]
pub enum IntersectionMessage {
    BindFragment(PaiBindFragment),
    ReplyFragment(PaiReplyFragment),
}

impl TryFrom<Message> for IntersectionMessage {
    type Error = ();
    fn try_from(message: Message) -> Result<Self, Self::Error> {
        match message {
            Message::PaiBindFragment(msg) => Ok(msg.into()),
            Message::PaiReplyFragment(msg) => Ok(msg.into()),
            _ => Err(()),
        }
    }
}

impl From<IntersectionMessage> for Message {
    fn from(message: IntersectionMessage) -> Self {
        match message {
            IntersectionMessage::BindFragment(msg) => msg.into(),
            IntersectionMessage::ReplyFragment(msg) => msg.into(),
        }
    }
}

// impl Encoder for ReconciliationMessage {
//     fn encoded_len(&self) -> usize {
//         Message::from(se)
//         todo!()
//     }
//
//     fn encode_into<W: std::io::Write>(&self, out: &mut W) -> anyhow::Result<()> {
//         todo!()
//     }
// }
//
// #[derive(Debug, derive_more::From)]
// pub enum ControlMessage {
//     CommitmentReveal(CommitmentReveal),
//     // TODO: move to CapabilityChannel
//     SetupBindReadCapability(SetupBindReadCapability),
//     // TODO: move to StaticTokenChannel
//     SetupBindStaticToken(SetupBindStaticToken),
//     // TODO: move to AreaOfInterestChannel
//     SetupBindAreaOfInterest(SetupBindAreaOfInterest),
//
//     IssueGuarantee(ControlIssueGuarantee),
//     Absolve(ControlAbsolve),
//     Plead(ControlPlead),
//     AnnounceDropping(ControlAnnounceDropping),
//     Apologise(ControlApologise),
//
//     FreeHandle(ControlFreeHandle),
// }
//
// impl From<ControlMessage> for Message {
//     fn from(message: ControlMessage) -> Self {
//         match message {
//             ControlMessage::CommitmentReveal(message) => message.into(),
//             ControlMessage::SetupBindReadCapability(message) => message.into(),
//             ControlMessage::SetupBindStaticToken(message) => message.into(),
//             ControlMessage::SetupBindAreaOfInterest(message) => message.into(),
//             ControlMessage::IssueGuarantee(message) => message.into(),
//             ControlMessage::Absolve(message) => message.into(),
//             ControlMessage::Plead(message) => message.into(),
//             ControlMessage::AnnounceDropping(message) => message.into(),
//             ControlMessage::Apologise(message) => message.into(),
//             ControlMessage::FreeHandle(message) => message.into(),
//         }
//     }
// }

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
    /// If this message is the last of a set of messages that together cover the range of some prior
    /// [`ReconciliationSendFingerprint`] message, then this field contains the range_count of that
    /// [`ReconciliationSendFingerprint`] message. Otherwise, none.
    pub covers: Option<u64>,
}

impl ReconciliationSendFingerprint {
    pub fn handles(&self) -> (AreaOfInterestHandle, AreaOfInterestHandle) {
        (self.receiver_handle, self.sender_handle)
    }
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
    /// If this message is the last of a set of messages that together cover the range of some prior
    /// [`ReconciliationSendFingerprint`] message, then this field contains the range_count of that
    /// [`ReconciliationSendFingerprint`] message. Otherwise, none.
    pub covers: Option<u64>,
}

impl ReconciliationAnnounceEntries {
    pub fn handles(&self) -> (AreaOfInterestHandle, AreaOfInterestHandle) {
        (self.receiver_handle, self.sender_handle)
    }
}

/// Transmit a [`LengthyEntry`] as part of 3d range-based set reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationSendEntry {
    /// The LengthyEntry itself.
    pub entry: LengthyEntry,
    /// A StaticTokenHandle, bound by the sender of this message, that is bound to the static part of the entry’s AuthorisationToken.
    pub static_token_handle: StaticTokenHandle,
    /// The dynamic part of the entry’s AuthorisationToken.
    pub dynamic_token: DynamicToken,
}

/// Transmit some transformed Payload bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationSendPayload {
    // A substring of the bytes obtained by applying transform_payload to the Payload to be transmitted.
    pub bytes: bytes::Bytes,
}

/// Indicate that no more bytes will be transmitted for the currently transmitted Payload as part of set reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationTerminatePayload;

/// Transmit an AuthorisedEntry to the other peer, and optionally prepare transmission of its Payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSendEntry {
    /// The Entry to transmit.
    pub entry: Entry,
    /// A [`StaticTokenHandle`] bound to the StaticToken of the Entry to transmit.
    pub static_token_handle: StaticTokenHandle,
    /// The DynamicToken of the Entry to transmit.
    pub dynamic_token: DynamicToken,
    /// The offset in the Payload in bytes at which Payload transmission will begin.
    ///
    /// If this is equal to the Entry’s payload_length, the Payload will not be transmitted.
    pub offset: u64,
}

/// Transmit some transformed Payload bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSendPayload {
    // A substring of the bytes obtained by applying transform_payload to the Payload to be transmitted.
    pub bytes: bytes::Bytes,
}

/// Express preferences for Payload transfer in the intersection of two AreaOfInterests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSetMetadata {
    /// An AreaOfInterestHandle, bound by the sender of this message.
    sender_handle: AreaOfInterestHandle,
    /// An AreaOfInterestHandle, bound by the receiver of this message.
    receiver_handle: AreaOfInterestHandle,
    // Whether the other peer should eagerly forward Payloads in this intersection.
    is_eager: bool,
}

// /// Bind an Entry to a PayloadRequestHandle and request transmission of its Payload from an offset.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct DataBindPayloadRequest {
//     /// The Entry to request.
//     entry: Entry,
//     /// The offset in the Payload starting from which the sender would like to receive the Payload bytes.
//     offset: u64,
//     /// A resource handle for a ReadCapability bound by the sender that grants them read access to the bound Entry.
//     capability: CapabilityHandle,
// }
//
// /// Set up the state for replying to a DataBindPayloadRequest message.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct DataReplyPayload {
//     /// The PayloadRequestHandle to which to reply.
//     handle: u64,
// }

/// An Entry together with information about how much of its Payload a peer holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        write!(f, "Fingerprint({})", iroh_base::base32::fmt_short(self.0))
    }
}

impl Fingerprint {
    pub fn add_entry(&mut self, entry: &Entry) {
        // TODO: Don't allocate
        let next =
            Fingerprint(*Hash::new(entry.encode().expect("encoding not to fail")).as_bytes());
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

pub type PsiGroupBytes = [u8; 32];

/// Bind data to an IntersectionHandle for performing private area intersection.
#[derive(derive_more::Debug, Serialize, Deserialize)]
pub struct PaiBindFragment {
    /// The result of first applying hash_into_group to some fragment for private area intersection and then performing scalar multiplication with scalar.
    #[debug("{}", hex::encode(self.group_member))]
    pub group_member: PsiGroupBytes,
    /// Set to true if the private set intersection item is a secondary fragment.
    pub is_secondary: bool,
}

/// Finalise private set intersection for a single item.
#[derive(derive_more::Debug, Serialize, Deserialize)]
pub struct PaiReplyFragment {
    /// The IntersectionHandle of the PaiBindFragment message which this finalises.
    pub handle: IntersectionHandle,
    /// The result of performing scalar multiplication between the group_member of the message that this is replying to and scalar.
    #[debug("{}", hex::encode(self.group_member))]
    pub group_member: PsiGroupBytes,
}

/// Ask the receiver to send a SubspaceCapability.
#[derive(Debug, Serialize, Deserialize)]
pub struct PaiRequestSubspaceCapability {
    /// The IntersectionHandle bound by the sender for the least-specific secondary fragment for whose NamespaceId to request the SubspaceCapability.
    pub handle: IntersectionHandle,
}

/// Send a previously requested SubspaceCapability.
#[derive(Debug, Serialize, Deserialize)]
pub struct PaiReplySubspaceCapability {
    /// The handle of the PaiRequestSubspaceCapability message that this answers (hence, an IntersectionHandle bound by the receiver of this message).
    pub handle: IntersectionHandle,
    /// A SubspaceCapability whose granted namespace corresponds to the request this answers.
    pub capability: SubspaceCapability,
    /// The SyncSubspaceSignature issued by the receiver of the capability over the sender’s challenge.
    pub signature: SyncSignature,
}
