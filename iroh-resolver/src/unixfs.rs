use std::{
    collections::VecDeque,
    fmt::Debug,
    io::Cursor,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes};
use cid::Cid;
use futures::{future::BoxFuture, FutureExt};
use prost::Message;
use tokio::io::AsyncRead;

use crate::{
    codecs::Codec,
    resolver::{ContentLoader, OutMetrics},
};

pub(crate) mod unixfs_pb {
    include!(concat!(env!("OUT_DIR"), "/unixfs_pb.rs"));
}

pub(crate) mod dag_pb {
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

#[derive(Debug, PartialEq)]
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

    pub fn encode(&self) -> Result<Bytes> {
        match self {
            UnixfsNode::Raw { data } => Ok(data.clone()),
            UnixfsNode::Pb { outer, .. } => {
                let bytes = outer.encode_to_vec();
                Ok(bytes.into())
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

    /// Returns the size in bytes of the underlying data.
    /// Available only for `Raw` and `File` which are a single block with no links.
    pub fn size(&self) -> Option<usize> {
        match self {
            UnixfsNode::Raw { data } => Some(data.len()),
            UnixfsNode::Pb { outer, inner } => {
                if outer.links.is_empty() {
                    return Some(inner.data.as_ref().map(|d| d.len()).unwrap_or_default());
                }

                None
            }
        }
    }

    pub fn links(&self) -> Links {
        match self {
            UnixfsNode::Raw { .. } => Links::Raw,
            UnixfsNode::Pb { outer, .. } => Links::Pb { i: 0, outer },
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.typ(), Some(DataType::Directory))
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

    fn cid_links(&self) -> VecDeque<Cid> {
        match self {
            UnixfsNode::Pb { outer, .. } => {
                outer
                    .links
                    .iter()
                    .map(|h| {
                        // TODO: error handling
                        Cid::read_bytes(Cursor::new(h.hash.as_deref().unwrap())).unwrap()
                    })
                    .collect()
            }
            UnixfsNode::Raw { .. } => Default::default(),
        }
    }

    pub fn symlink(&self) -> Result<Option<&str>> {
        if self.typ() == Some(DataType::Symlink) {
            match self {
                UnixfsNode::Pb { inner, .. } => {
                    let link = std::str::from_utf8(inner.data.as_deref().unwrap_or_default())?;
                    Ok(Some(link))
                }
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    pub fn pretty<T: ContentLoader>(self, loader: T, om: OutMetrics) -> UnixfsReader<T> {
        let current_links = vec![self.cid_links()];

        UnixfsReader {
            root_node: self,
            pos: 0,
            current_node: CurrentNodeState::Outer,
            current_links,
            loader,
            out_metrics: om,
        }
    }
}

// #[derive(Debug)]
pub struct UnixfsReader<T: ContentLoader> {
    root_node: UnixfsNode,
    /// Absolute position in bytes
    pos: usize,
    /// Current node being operated on, only used for nested nodes (not the root).
    current_node: CurrentNodeState,
    /// Stack of links left to traverse.
    current_links: Vec<VecDeque<Cid>>,
    loader: T,
    out_metrics: OutMetrics,
}

impl<T: ContentLoader + Unpin + 'static> AsyncRead for UnixfsReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let typ = self.root_node.typ();
        let Self {
            root_node,
            current_node,
            current_links,
            pos,
            loader,
            out_metrics,
        } = &mut *self;
        let pos_current = *pos;
        let poll_res = match root_node {
            UnixfsNode::Raw { data } => {
                let res = poll_read_buf_at_pos(pos, data, buf);
                Poll::Ready(res)
            }
            UnixfsNode::Pb { outer, inner } => match typ.unwrap() {
                DataType::File => poll_read_file_at(
                    cx,
                    outer,
                    inner,
                    loader.clone(),
                    pos,
                    buf,
                    current_links,
                    current_node,
                ),
                DataType::Symlink => {
                    let data = inner.data.as_deref().unwrap_or_default();
                    let res = poll_read_buf_at_pos(pos, data, buf);
                    Poll::Ready(res)
                }
                DataType::Directory => {
                    // TODO: cache
                    let mut res = Vec::new();
                    for link in &outer.links {
                        if let Some(ref name) = link.name {
                            res.extend_from_slice(name.as_bytes());
                        }
                        res.extend_from_slice(b"\n");
                    }
                    let res = poll_read_buf_at_pos(pos, &res, buf);
                    Poll::Ready(res)
                }
                _ => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unsupported Unixfs type: {:?} ", typ),
                ))),
            },
        };
        let bytes_read = *pos - pos_current;
        out_metrics.observe_bytes_read(pos_current, bytes_read);
        poll_res
    }
}

pub fn poll_read_buf_at_pos(
    pos: &mut usize,
    data: &[u8],
    buf: &mut tokio::io::ReadBuf<'_>,
) -> std::io::Result<()> {
    if *pos >= data.len() {
        return Ok(());
    }
    let data_len = data.len() - *pos;
    let amt = std::cmp::min(data_len, buf.remaining());
    buf.put_slice(&data[*pos..*pos + amt]);
    *pos += amt;

    Ok(())
}

enum CurrentNodeState {
    Outer,
    None,
    Loaded(usize, UnixfsNode),
    Loading(BoxFuture<'static, Result<UnixfsNode>>),
}

impl Debug for CurrentNodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CurrentNodeState::Outer => write!(f, "CurrentNodeState::Outer"),
            CurrentNodeState::None => write!(f, "CurrentNodeState::None"),
            CurrentNodeState::Loaded(pos, n) => {
                write!(f, "CurrentNodeState::Loaded({:?}, {:?})", pos, n)
            }
            CurrentNodeState::Loading(_) => write!(f, "CurrentNodeState::Loading(Fut)"),
        }
    }
}

fn load_next_node<T: ContentLoader + 'static>(
    current_node: &mut CurrentNodeState,
    current_links: &mut Vec<VecDeque<Cid>>,
    loader: T,
) -> bool {
    // Load next node
    if current_links.is_empty() {
        // no links left we are done
        return true;
    }
    if current_links.last().unwrap().is_empty() {
        // remove emtpy
        current_links.pop();
    }

    let links = current_links.last_mut().unwrap();
    if links.is_empty() {
        return true;
    }

    let link = links.pop_front().unwrap();

    let fut = async move {
        let loaded_cid = loader.load_cid(&link).await?;
        let node = UnixfsNode::decode(&link, loaded_cid.data)?;
        Ok(node)
    }
    .boxed();
    *current_node = CurrentNodeState::Loading(fut);
    false
}

#[allow(clippy::too_many_arguments)]
fn poll_read_file_at<T: ContentLoader + 'static>(
    cx: &mut Context<'_>,
    root_outer: &dag_pb::PbNode,
    root_inner: &unixfs_pb::Data,
    loader: T,
    pos: &mut usize,
    buf: &mut tokio::io::ReadBuf<'_>,
    current_links: &mut Vec<VecDeque<Cid>>,
    current_node: &mut CurrentNodeState,
) -> Poll<std::io::Result<()>> {
    loop {
        match current_node {
            CurrentNodeState::Outer => {
                // check for links
                if root_outer.links.is_empty() {
                    // simplest case just one file
                    let data = root_inner.data.as_deref().unwrap_or(&[][..]);
                    let res = poll_read_buf_at_pos(pos, data, buf);
                    return Poll::Ready(res);
                }

                // read root local data
                if let Some(ref data) = root_inner.data {
                    if *pos < data.len() {
                        let res = poll_read_buf_at_pos(pos, data, buf);
                        return Poll::Ready(res);
                    }
                }
                *current_node = CurrentNodeState::None;
                if load_next_node(current_node, current_links, loader.clone()) {
                    return Poll::Ready(Ok(()));
                }
            }
            CurrentNodeState::None => {
                if load_next_node(current_node, current_links, loader.clone()) {
                    return Poll::Ready(Ok(()));
                }
            }
            CurrentNodeState::Loading(fut) => {
                // Already loading the next node, just wait
                match fut.poll_unpin(cx) {
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(node)) => {
                        current_links.push(node.cid_links());
                        *current_node = CurrentNodeState::Loaded(0, node);

                        // TODO: do one read
                    }
                    Poll::Ready(Err(e)) => {
                        *current_node = CurrentNodeState::None;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                }
            }
            CurrentNodeState::Loaded(ref mut node_pos, ref mut current_node_inner) => {
                // already loaded
                let ty = current_node_inner.typ();
                match current_node_inner {
                    UnixfsNode::Raw { data } => {
                        let old = *node_pos;
                        let res = poll_read_buf_at_pos(node_pos, data, buf);
                        // advance global pos
                        let amt_read = *node_pos - old;
                        *pos += amt_read;
                        if amt_read > 0 {
                            return Poll::Ready(res);
                        } else if *node_pos == data.len() {
                            // finished reading this node
                            if load_next_node(current_node, current_links, loader.clone()) {
                                return Poll::Ready(Ok(()));
                            }
                        }
                    }
                    UnixfsNode::Pb { inner, .. } => {
                        if ty == Some(DataType::File) || ty == Some(DataType::Raw) {
                            // read direct node data
                            if let Some(ref data) = inner.data {
                                let old = *node_pos;
                                let res = poll_read_buf_at_pos(node_pos, data, buf);
                                let amt_read = *node_pos - old;
                                *pos += amt_read;
                                if amt_read > 0 {
                                    return Poll::Ready(res);
                                }
                            }

                            // follow links
                            if load_next_node(current_node, current_links, loader.clone()) {
                                return Poll::Ready(Ok(()));
                            }
                        } else {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("invalid type nested in chunked file: {:?}", ty),
                            )));
                        }
                    }
                }
            }
        }
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
