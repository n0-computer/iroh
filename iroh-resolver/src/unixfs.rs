use std::io::Cursor;

use anyhow::{anyhow, bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use cid::Cid;
use prost::Message;

use crate::{codecs::Codec, resolver::ContentLoader};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRef<'a> {
    pub cid: Cid,
    pub name: Option<&'a str>,
    pub tsize: Option<u64>,
}

#[derive(Debug)]
pub enum UnixfsNode {
    Raw {
        data: Bytes,
    },
    Pb {
        outer: dag_pb::PbNode,
        inner: unixfs_pb::Data,
    },
}

impl UnixfsNode {
    pub fn decode(cid: &Cid, buf: Bytes) -> Result<Self> {
        match cid.codec() {
            c if c == Codec::Raw as u64 => Ok(UnixfsNode::Raw { data: buf }),
            _ => {
                let outer = dag_pb::PbNode::decode(buf)?;
                let inner_data = outer
                    .data
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| anyhow!("missing data"))?;
                let inner = unixfs_pb::Data::decode(inner_data)?;
                // ensure correct unixfs type
                let _typ: DataType = inner.r#type.try_into()?;

                Ok(UnixfsNode::Pb { outer, inner })
            }
        }
    }

    pub fn typ(&self) -> Option<DataType> {
        match self {
            UnixfsNode::Raw { .. } => None,
            UnixfsNode::Pb { inner, .. } => {
                Some(inner.r#type.try_into().expect("invalid data type"))
            }
        }
    }

    pub fn links(&self) -> Links {
        match self {
            UnixfsNode::Raw { .. } => Links::Raw,
            UnixfsNode::Pb { outer, .. } => Links::Pb { i: 0, outer },
        }
    }

    pub async fn get_link_by_name<S: AsRef<str>>(
        &self,
        link_name: S,
    ) -> Result<Option<LinkRef<'_>>> {
        let link_name = link_name.as_ref();
        self.links()
            .find(|l| match l {
                Ok(l) => l.name == Some(link_name),
                _ => false,
            })
            .transpose()
    }

    pub async fn pretty(&self, loader: &dyn ContentLoader) -> Result<Bytes> {
        match self {
            UnixfsNode::Raw { data } => Ok(data.clone()),
            UnixfsNode::Pb { outer, inner } => match self.typ().unwrap() {
                DataType::File => read_file(outer, inner, loader).await,
                DataType::Directory => {
                    let mut res = String::new();
                    for link in &outer.links {
                        if let Some(ref name) = link.name {
                            res += name;
                        }
                        res += "\n";
                    }

                    Ok(Bytes::from(res))
                }
                _ => bail!("not implemented: {:?}", self.typ()),
            },
        }
    }
}

#[async_recursion::async_recursion]
async fn read_file(
    outer: &dag_pb::PbNode,
    inner: &unixfs_pb::Data,
    loader: &dyn ContentLoader,
) -> Result<Bytes> {
    if outer.links.is_empty() {
        // simplest case just one file
        Ok(inner.data.as_ref().cloned().unwrap_or_default())
    } else {
        let mut out = BytesMut::new();
        if let Some(data) = inner.data.as_ref() {
            out.put(&data[..]);
        }

        for link in &outer.links {
            let cid_raw = link.hash.as_ref().ok_or_else(|| anyhow!("missing cid"))?;
            let cid = Cid::read_bytes(Cursor::new(cid_raw))?;

            let raw_next = loader.load_cid(&cid).await?;
            let node_next = UnixfsNode::decode(&cid, raw_next)?;
            let ty = node_next.typ();

            match node_next {
                UnixfsNode::Raw { data } => {
                    out.put(&data[..]);
                }
                UnixfsNode::Pb { outer, inner } => {
                    if ty == Some(DataType::File) || ty == Some(DataType::Raw) {
                        if let Some(data) = inner.data.as_ref() {
                            out.put(&data[..]);
                        }

                        let bytes = read_file(&outer, &inner, loader).await?;
                        out.put(&bytes[..]);
                    } else {
                        bail!("invalid type nested in chunked file: {:?}", ty);
                    }
                }
            }
        }

        Ok(out.freeze())
    }
}

#[derive(Debug)]
pub enum Links<'a> {
    Raw,
    Pb { i: usize, outer: &'a dag_pb::PbNode },
}

impl<'a> Iterator for Links<'a> {
    type Item = Result<LinkRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Links::Raw => None,
            Links::Pb { i, outer } => {
                if *i == outer.links.len() {
                    return None;
                }

                let l = &outer.links[*i];
                *i += 1;

                let res = l
                    .hash
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing link"))
                    .and_then(|c| {
                        Ok(LinkRef {
                            cid: Cid::read_bytes(Cursor::new(c))?,
                            name: l.name.as_deref(),
                            tsize: l.tsize,
                        })
                    });

                Some(res)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Links::Raw => (0, Some(0)),
            Links::Pb { outer, .. } => (outer.links.len(), Some(outer.links.len())),
        }
    }
}
