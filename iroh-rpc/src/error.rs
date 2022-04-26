use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};
use std::fmt;

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum RPCError {
    TODO,
    MethodNotFound,
    NamespaceNotFound,
    BadRequest,
    BadResponse,
    StreamClosed,
}

impl fmt::Display for RPCError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RPCError::TODO => write!(f, "TODO: Implement error"),
            RPCError::MethodNotFound => write!(f, "Method Not Found"),
            RPCError::NamespaceNotFound => write!(f, "Namespace Not Found"),
            RPCError::BadRequest => write!(f, "Bad Request"),
            RPCError::BadResponse => write!(f, "Bad Response"),
            RPCError::StreamClosed => write!(f, "Stream Closed"),
        }
    }
}

impl std::error::Error for RPCError {}
