use anyhow::{anyhow, bail, Result};
use bytes::{Buf, Bytes};
use cid::Cid;
use prost::Message;

mod unixfs_pb {
    include!(concat!(env!("OUT_DIR"), "/unixfs_pb.rs"));
}

mod dag_pb {
    include!(concat!(env!("OUT_DIR"), "/merkledag_pb.rs"));
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, num_enum::IntoPrimitive, num_enum::TryFromPrimitive,
)]
#[repr(i32)]
pub enum DataType {
    Raw = 0,
    Directory = 1,
    File = 2,
    Metadata = 3,
    Symlink = 4,
    HamtShard = 5,
}

#[derive(Debug, Clone)]
pub struct Unixfs {
    inner: unixfs_pb::Data,
}

impl Unixfs {
    pub fn from_bytes<B: Buf>(bytes: B) -> Result<Self> {
        let proto = unixfs_pb::Data::decode(bytes)?;

        Ok(Unixfs { inner: proto })
    }

    pub fn typ(&self) -> DataType {
        self.inner.r#type.try_into().expect("invalid data type")
    }

    pub fn data(&self) -> Option<&Bytes> {
        self.inner.data.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub cid: Cid,
    pub name: Option<String>,
    pub tsize: Option<u64>,
}

#[derive(Debug)]
pub struct UnixfsNode {
    outer: dag_pb::PbNode,
    inner: unixfs_pb::Data,
}

impl UnixfsNode {
    pub fn decode<B: Buf>(buf: B) -> Result<Self> {
        let outer = dag_pb::PbNode::decode(buf)?;
        let inner_data = outer
            .data
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("missing data"))?;
        let inner = unixfs_pb::Data::decode(inner_data)?;
        // ensure correct unixfs type
        let _typ: DataType = inner.r#type.try_into()?;

        Ok(Self { outer, inner })
    }

    pub fn typ(&self) -> DataType {
        self.inner.r#type.try_into().expect("invalid data type")
    }

    pub async fn get_link_by_name<S: AsRef<str>>(&self, _link: S) -> Result<Option<Link>> {
        todo!()
    }

    pub fn pretty(&self) -> Result<Bytes> {
        match self.typ() {
            DataType::File => {
                if self.outer.links.is_empty() {
                    // simplest case just one file
                    Ok(self.inner.data.as_ref().cloned().unwrap_or_default())
                } else {
                    bail!("not implemented")
                }
            }
            _ => bail!("not implemented"),
        }
    }
}
