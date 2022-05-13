use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};
use thiserror::Error;

#[derive(Archive, Serialize, Deserialize, Error, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum RpcError {
    #[error("TODO: Implement error")]
    TODO,
    #[error("Method `{0}` not found")]
    MethodNotFound(String), // emitted by the server if there are no handlers for this method
    #[error("Namespace `{0}` not found")]
    NamespaceNotFound(String), // emitted by the server if there are no methods for this namespace
    #[error("No address set for namespace `{0}`")]
    NoNamespaceAddress(String), // emitted by the client if there are no addresses set for this namespace
    #[error("No peer id set for namespace `{0}`")]
    NoNamespacePeerId(String), // emitted by the client if there is no peer id set for htis namespace
    #[error("Bad Request")]
    BadRequest,
    #[error("Bad Response")]
    BadResponse,
    #[error("Stream Closed")]
    StreamClosed,
    #[error("No Stream Configuration")]
    NoStreamConfig,
    #[error("Reached Buffer Max")]
    BufferMax,
    #[error("Bad config: `{0}`")]
    BadConfig(String),
    #[error("Unexpected response type `{0}`")]
    UnexpectedResponseType(String),
    #[error("Unexpected request type: `{0}")]
    UnexpectedRequestType(String),
    #[error("DialError: `{0}`")]
    DialError(String),
    #[error("OutboundFailure: `{0}`")]
    OutboundFailure(String),
    #[error("TransportError: `{0}`")]
    TransportError(String),
    #[error("SerializeError: `{0}`")]
    SerializeError(String),
    #[error("DeserializeError: `{0}`")]
    DeserializeError(String),
}
