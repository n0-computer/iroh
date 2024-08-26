use iroh_base::rpc::{RpcError, RpcResult};
use iroh_net::NodeId;
use iroh_willow::{
    form::{AuthForm, SerdeEntryOrForm},
    interest::{CapSelector, CapabilityPack, DelegateTo},
    proto::{
        data_model::{self, serde_encoding::SerdeEntry, AuthorisedEntry},
        grouping::{self, Range3d},
        keys::{NamespaceId, NamespaceKind, UserId},
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
    #[rpc(response = RpcResult<IngestEntryResponse>)]
    IngestEntry(IngestEntryRequest),
    #[rpc(response = RpcResult<InsertEntryResponse>)]
    InsertEntry(InsertEntryRequest),
    #[rpc(response = RpcResult<InsertSecretResponse>)]
    InsertSecret(InsertSecretRequest),
    #[try_server_streaming(create_error = RpcError, item_error = RpcError, item = GetEntriesResponse)]
    GetEntries(GetEntriesRequest),
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
    IngestEntry(RpcResult<IngestEntryResponse>),
    InsertEntry(RpcResult<InsertEntryResponse>),
    InsertSecret(RpcResult<InsertSecretResponse>),
    GetEntries(RpcResult<GetEntriesResponse>),
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
pub struct IngestEntryResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct InsertEntryRequest {
    pub entry: SerdeEntryOrForm,
    pub auth: AuthForm,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InsertEntryResponse;

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
pub struct GetEntriesResponse(pub SerdeEntry);

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

// #[derive(Debug, Serialize, Deserialize)]
// pub struct ResolveInterestsRequest {
//     pub interests: Interests,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct ResolveInterestsResponse(pub InterestMap);

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
