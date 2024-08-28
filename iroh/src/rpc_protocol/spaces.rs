use iroh_base::rpc::{RpcError, RpcResult};
use iroh_blobs::Hash;
use iroh_net::NodeId;
use iroh_willow::{
    form::{AuthForm, SubspaceForm, TimestampForm},
    interest::{CapSelector, CapabilityPack, DelegateTo},
    proto::{
        data_model::{
            self, serde_encoding::SerdeAuthorisedEntry, AuthorisedEntry, Entry, NamespaceId, Path,
            SubspaceId,
        },
        grouping::{self, Range3d},
        keys::{NamespaceKind, UserId},
        meadowcap::{self, AccessMode, SecretKey},
    },
    session::{
        intents::{serde_encoding::Event, IntentUpdate},
        SessionInit,
    },
};
use nested_enum_utils::enum_conversions;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use super::RpcService;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[rpc(response = RpcResult<IngestEntrySuccess>)]
    IngestEntry(IngestEntryRequest),
    #[rpc(response = RpcResult<InsertEntrySuccess>)]
    InsertEntry(InsertEntryRequest),
    #[rpc(response = RpcResult<InsertSecretResponse>)]
    InsertSecret(InsertSecretRequest),
    #[try_server_streaming(create_error = RpcError, item_error = RpcError, item = GetEntriesResponse)]
    GetEntries(GetEntriesRequest),
    #[rpc(response = RpcResult<GetEntryResponse>)]
    GetEntry(GetEntryRequest),
    #[rpc(response = RpcResult<CreateNamespaceResponse>)]
    CreateNamespace(CreateNamespaceRequest),
    #[rpc(response = RpcResult<CreateUserResponse>)]
    CreateUser(CreateUserRequest),
    #[rpc(response = RpcResult<DelegateCapsResponse>)]
    DelegateCaps(DelegateCapsRequest),
    #[rpc(response = RpcResult<ImportCapsResponse>)]
    ImportCaps(ImportCapsRequest),
    // #[rpc(response = RpcResult<ResolveInterestsResponse>)]
    // ResolveInterests(ResolveInterestsRequest),
    #[bidi_streaming(update = SyncWithPeerUpdate, response = RpcResult<SyncWithPeerResponse>)]
    SyncWithPeer(SyncWithPeerRequest),
    SyncWithPeerUpdate(SyncWithPeerUpdate),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Response)]
pub enum Response {
    IngestEntry(RpcResult<IngestEntrySuccess>),
    InsertEntry(RpcResult<InsertEntrySuccess>),
    InsertSecret(RpcResult<InsertSecretResponse>),
    GetEntries(RpcResult<GetEntriesResponse>),
    GetEntry(RpcResult<GetEntryResponse>),
    CreateNamespace(RpcResult<CreateNamespaceResponse>),
    CreateUser(RpcResult<CreateUserResponse>),
    DelegateCaps(RpcResult<DelegateCapsResponse>),
    ImportCaps(RpcResult<ImportCapsResponse>),
    // ResolveInterests(RpcResult<ResolveInterestsResponse>),
    SyncWithPeer(RpcResult<SyncWithPeerResponse>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngestEntryRequest {
    #[serde(with = "data_model::serde_encoding::authorised_entry")]
    pub authorised_entry: AuthorisedEntry,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InsertEntryRequest {
    pub entry: FullEntryForm,
    pub auth: AuthForm,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum InsertEntrySuccess {
    Inserted(#[serde(with = "data_model::serde_encoding::authorised_entry")] AuthorisedEntry),
    Obsolete,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IngestEntrySuccess {
    Inserted,
    Obsolete,
}

impl InsertEntrySuccess {
    /// Returns the inserted entry, or an error if the entry was not inserted
    /// because it is obsoleted by a newer entry.
    pub fn inserted(self) -> Result<AuthorisedEntry, EntryObsoleteError> {
        match self {
            Self::Inserted(entry) => Ok(entry),
            Self::Obsolete => Err(EntryObsoleteError),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("The entry was not inserted because a newer entry exists.")]
pub struct EntryObsoleteError;

#[derive(Debug, Serialize, Deserialize)]
pub struct InsertSecretRequest {
    pub secret: SecretKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InsertSecretResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct GetEntriesRequest {
    pub namespace: NamespaceId,
    #[serde(with = "grouping::serde_encoding::range_3d")]
    pub range: Range3d,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetEntriesResponse(
    #[serde(with = "data_model::serde_encoding::authorised_entry")] pub AuthorisedEntry,
);

#[derive(Debug, Serialize, Deserialize)]
pub struct GetEntryRequest {
    pub namespace: NamespaceId,
    pub subspace: SubspaceId,
    #[serde(with = "data_model::serde_encoding::path")]
    pub path: Path,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetEntryResponse(
    pub Option<SerdeAuthorisedEntry>, // #[serde(with = "data_model::serde_encoding::authorised_entry")] pub AuthorisedEntry,
);

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateNamespaceRequest {
    pub kind: NamespaceKind,
    pub owner: UserId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateNamespaceResponse(pub NamespaceId);

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserResponse(pub UserId);

#[derive(Debug, Serialize, Deserialize)]
pub struct DelegateCapsRequest {
    pub from: CapSelector,
    #[serde(with = "meadowcap::serde_encoding::access_mode")]
    pub access_mode: AccessMode,
    pub to: DelegateTo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DelegateCapsResponse(pub Vec<CapabilityPack>);

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportCapsRequest {
    pub caps: Vec<CapabilityPack>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportCapsResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncWithPeerRequest {
    pub peer: NodeId,
    pub init: SessionInit,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncWithPeerUpdate(pub IntentUpdate);

#[derive(Debug, Serialize, Deserialize)]
pub enum SyncWithPeerResponse {
    Started,
    Event(Event),
}

/// Either a complete [`Entry`] or a [`FullEntryForm`].
#[derive(Debug, Serialize, Deserialize)]
pub enum EntryOrForm {
    Entry(#[serde(with = "data_model::serde_encoding::entry")] Entry),
    Form(FullEntryForm),
}

impl From<EntryOrForm> for iroh_willow::form::EntryOrForm {
    fn from(value: EntryOrForm) -> Self {
        match value {
            EntryOrForm::Entry(entry) => Self::Entry(entry),
            EntryOrForm::Form(form) => Self::Form(form.into()),
        }
    }
}

/// Creates an entry while setting some fields automatically.
#[derive(Debug, Serialize, Deserialize)]
pub struct FullEntryForm {
    pub namespace_id: NamespaceId,
    pub subspace_id: SubspaceForm,
    #[serde(with = "data_model::serde_encoding::path")]
    pub path: Path,
    pub timestamp: TimestampForm,
    pub payload: PayloadForm,
}

impl From<FullEntryForm> for iroh_willow::form::EntryForm {
    fn from(value: FullEntryForm) -> Self {
        Self {
            namespace_id: value.namespace_id,
            subspace_id: value.subspace_id,
            path: value.path,
            timestamp: value.timestamp,
            payload: value.payload.into(),
        }
    }
}

/// Options for setting the payload on the a new entry.
#[derive(Debug, Serialize, Deserialize)]
pub enum PayloadForm {
    /// Make sure the hash is available in the blob store, and use the length from the blob store.
    Checked(Hash),
    /// Insert with the specified hash and length, without checking if the blob is in the local blob store.
    Unchecked(Hash, u64),
}

impl From<PayloadForm> for iroh_willow::form::PayloadForm {
    fn from(value: PayloadForm) -> Self {
        match value {
            PayloadForm::Checked(hash) => Self::Hash(hash),
            PayloadForm::Unchecked(hash, len) => Self::HashUnchecked(hash, len),
        }
    }
}
