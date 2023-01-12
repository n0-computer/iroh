use std::io::{self, Read, Seek};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Reference to some data in a file
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReference {
    pub path: String,
    pub offset: u64,
    pub len: usize,
}

/// Data with optional provenance
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytesWithProvenance {
    pub data: Bytes,
    pub provenance: Option<FileReference>,
}

impl BytesWithProvenance {
    pub fn new(data: Bytes, provenance: Option<FileReference>) -> Self {
        Self { data, provenance }
    }
}

impl From<Bytes> for BytesWithProvenance {
    fn from(data: Bytes) -> Self {
        Self {
            data,
            provenance: None,
        }
    }
}

/// A blob or a reference to a file
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BytesOrReference {
    Bytes(Bytes),
    Reference(FileReference),
}

impl From<Bytes> for BytesOrReference {
    fn from(value: Bytes) -> Self {
        Self::Bytes(value)
    }
}

impl From<BytesWithProvenance> for BytesOrReference {
    fn from(value: BytesWithProvenance) -> Self {
        match value.provenance {
            Some(reference) => Self::Reference(reference),
            None => Self::Bytes(value.data),
        }
    }
}

impl BytesOrReference {
    pub fn size(&self) -> usize {
        match self {
            BytesOrReference::Bytes(b) => b.len(),
            BytesOrReference::Reference(r) => r.len,
        }
    }

    /// load the data from disk, in case the block is a reference
    pub fn load(&self) -> io::Result<Bytes> {
        match self {
            BytesOrReference::Bytes(b) => Ok(b.clone()),
            BytesOrReference::Reference(r) => {
                println!(
                    "loading slice from {} at {} of length {}",
                    r.path, r.offset, r.len
                );
                let mut file = std::fs::File::open(&r.path)?;
                file.seek(std::io::SeekFrom::Start(r.offset))?;
                let mut buf = vec![0; r.len];
                file.read_exact(&mut buf)?;
                Ok(Bytes::from(buf))
            }
        }
    }
}
