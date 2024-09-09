use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::{
    proto::{
        data_model::serde_encoding::SerdeEntry,
        data_model::Entry,
        grouping::{
            serde_encoding::{SerdeAreaOfInterest, SerdeRange3d},
            Area,
        },
        meadowcap::{self},
        wgps::AccessChallenge,
    },
    util::codec::{DecodeOutcome, Decoder, Encoder},
};

use super::{
    channels::LogicalChannel,
    fingerprint::Fingerprint,
    handles::{
        AreaOfInterestHandle, CapabilityHandle, HandleType, IntersectionHandle, StaticTokenHandle,
    },
};

pub type StaticToken = meadowcap::serde_encoding::SerdeMcCapability;
// pub type ValidatedStaticToken = meadowcap::ValidatedCapability;
pub type DynamicToken = meadowcap::UserSignature;

/// Whereas write access control is baked into the Willow data model,
/// read access control resides in the replication layer.
/// To manage read access via capabilities, all peers must cooperate in sending Entries only to peers
/// who have presented a valid read capability for the Entry.
/// We describe the details in a capability-system-agnostic way here.
/// To use Meadowcap for this approach, simply choose the type of valid McCapabilities with access mode read as the read capabilities.
pub type ReadCapability = meadowcap::serde_encoding::SerdeMcCapability;

/// Whenever a peer is granted a complete read capability of non-empty path,
/// it should also be granted a corresponding subspace capability.
/// Each subspace capability must have a single receiver (a public key of some signature scheme),
/// and a single granted namespace (a NamespaceId).
/// The receiver can authenticate itself by signing a collaboratively selected nonce.
pub type SubspaceCapability = meadowcap::serde_encoding::SerdeMcSubspaceCapability;

pub type SyncSignature = meadowcap::UserSignature;

pub type Receiver = meadowcap::UserPublicKey;

/// An Entry together with information about how much of its Payload a peer holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LengthyEntry {
    /// The Entry in question.
    pub entry: SerdeEntry,
    /// The number of consecutive bytes from the start of the entry’s Payload that the peer holds.
    pub available: u64,
}

impl LengthyEntry {
    pub fn new(entry: Entry, available: u64) -> Self {
        Self {
            entry: entry.into(),
            available,
        }
    }
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

/// Complete the commitment scheme to determine the challenge for read authentication.
#[derive(Serialize, Deserialize, PartialEq, Eq, derive_more::Debug)]
pub struct CommitmentReveal {
    /// The nonce of the sender, encoded as a big-endian unsigned integer.
    #[debug("{}..", iroh_base::base32::fmt_short(self.nonce.as_bytes()))]
    pub nonce: AccessChallenge,
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
    pub area_of_interest: SerdeAreaOfInterest,
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
    pub range: SerdeRange3d,
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
    pub range: SerdeRange3d,
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
#[derive(derive_more::Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationSendPayload {
    // A substring of the bytes obtained by applying transform_payload to the Payload to be transmitted.
    #[debug("Bytes({})", self.bytes.len())]
    pub bytes: bytes::Bytes,
}

/// Indicate that no more bytes will be transmitted for the currently transmitted Payload as part of set reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationTerminatePayload;

/// Transmit an AuthorisedEntry to the other peer, and optionally prepare transmission of its Payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSendEntry {
    /// The Entry to transmit.
    pub entry: SerdeEntry,
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
