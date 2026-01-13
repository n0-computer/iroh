use std::{
    fmt, io,
    sync::Arc,
    task::{Context, Poll},
};

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};

use super::{Addr, Transmit};

/// User transport factory
pub trait UserTransportFactory: std::fmt::Debug + Send + Sync + 'static {
    /// Create an actual user transport
    fn bind(&self) -> io::Result<Box<dyn UserTransport>>;
}

/// An user transport
pub trait UserTransport: std::fmt::Debug + Send + Sync + 'static {
    /// Watch local addrs
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<UserAddr>>;
    /// Create a sender
    fn create_sender(&self) -> Arc<dyn UserSender>;
    /// Poll recv
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>>;
}

/// User sender
pub trait UserSender: std::fmt::Debug + Send + Sync + 'static {
    /// is addr valid for this transport?
    fn is_valid_send_addr(&self, addr: &UserAddr) -> bool;
    /// poll_send
    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        dst: UserAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>>;
}

/// TODO
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserAddr {
    /// id
    id: u64,
    /// data
    data: UserAddrBytes,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum UserAddrBytes {
    Inline { size: u8, data: [u8; 30] },
    Heap(Box<[u8]>),
}

impl fmt::Debug for UserAddrBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            write!(f, "[{}]", HEXLOWER.encode(self.as_bytes()))
        } else {
            let bytes = self.as_bytes();
            match self {
                Self::Inline { .. } => write!(f, "Inline[{}]", HEXLOWER.encode(bytes)),
                Self::Heap(_) => write!(f, "Heap[{}]", HEXLOWER.encode(bytes)),
            }
        }
    }
}

impl From<(u64, &[u8])> for UserAddr {
    fn from((id, data): (u64, &[u8])) -> Self {
        Self::from_parts(id, data)
    }
}

impl UserAddrBytes {
    pub fn len(&self) -> usize {
        match self {
            Self::Inline { size, .. } => *size as usize,
            Self::Heap(data) => data.len(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Inline { size, data } => &data[..*size as usize],
            Self::Heap(data) => data,
        }
    }

    pub fn copy_from_slice(data: &[u8]) -> Self {
        if data.len() <= 30 {
            let mut inline = [0u8; 30];
            inline[..data.len()].copy_from_slice(data);
            Self::Inline {
                size: data.len() as u8,
                data: inline,
            }
        } else {
            Self::Heap(data.to_vec().into_boxed_slice())
        }
    }
}

impl UserAddr {
    /// Creates a new [`UserAddr`] from its parts.
    pub fn from_parts(id: u64, data: &[u8]) -> Self {
        Self {
            id,
            data: UserAddrBytes::copy_from_slice(data),
        }
    }

    /// Id to distinguish different user address types
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Data associated with this user address
    pub fn data(&self) -> &[u8] {
        self.data.as_bytes()
    }

    /// Convert to byte representation
    pub fn as_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.data.len());
        out[..8].copy_from_slice(&self.id().to_le_bytes());
        out[8..].copy_from_slice(self.data());
        out
    }

    /// Parse from bytes
    pub fn from_bytes(_data: &[u8]) -> Result<Self, &'static str> {
        todo!()
    }
}
