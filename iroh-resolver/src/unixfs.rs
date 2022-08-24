use std::{
    collections::VecDeque,
    fmt::Debug,
    io::Cursor,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{anyhow, bail, ensure, Result};
use bytes::{Buf, Bytes};
use cid::{multihash::MultihashDigest, Cid};
use futures::{future::BoxFuture, stream::BoxStream, FutureExt, Stream, StreamExt};
use prost::Message;
use tokio::io::AsyncRead;

use crate::{
    chunker::DEFAULT_CHUNK_SIZE_LIMIT,
    codecs::Codec,
    hamt::Hamt,
    resolver::{ContentLoader, LoaderContext, OutMetrics, Path, Resolver},
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

impl Link {
    pub fn as_ref(&self) -> LinkRef<'_> {
        LinkRef {
            cid: self.cid,
            name: self.name.as_deref(),
            tsize: self.tsize,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRef<'a> {
    pub cid: Cid,
    pub name: Option<&'a str>,
    pub tsize: Option<u64>,
}

impl LinkRef<'_> {
    pub fn to_owned(&self) -> Link {
        Link {
            cid: self.cid,
            name: self.name.map(|t| t.to_string()),
            tsize: self.tsize,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum UnixfsNode {
    Raw(Bytes),
    RawNode(Node),
    Directory(Node),
    File(Node),
    Symlink(Node),
    HamtShard(Node, Hamt),
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, num_enum::IntoPrimitive, num_enum::TryFromPrimitive, Hash,
)]
#[repr(u64)]
pub enum HamtHashFunction {
    /// Murmur3 6464
    Murmur3 = 0x22,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Node {
    pub(super) outer: dag_pb::PbNode,
    pub(super) inner: unixfs_pb::Data,
}

impl Node {
    fn encode(&self) -> Result<Bytes> {
        let bytes = self.outer.encode_to_vec();
        Ok(bytes.into())
    }

    pub fn typ(&self) -> DataType {
        self.inner.r#type.try_into().expect("invalid data type")
    }

    pub fn data(&self) -> Option<Bytes> {
        self.inner.data.clone()
    }

    pub fn filesize(&self) -> Option<u64> {
        self.inner.filesize
    }

    pub fn blocksizes(&self) -> &[u64] {
        &self.inner.blocksizes
    }

    pub fn size(&self) -> Option<usize> {
        if self.outer.links.is_empty() {
            return Some(
                self.inner
                    .data
                    .as_ref()
                    .map(|d| d.len())
                    .unwrap_or_default(),
            );
        }

        None
    }

    pub fn links(&self) -> Links {
        match self.typ() {
            DataType::Raw => Links::RawNode(PbLinks::new(&self.outer)),
            DataType::Directory => Links::Directory(PbLinks::new(&self.outer)),
            DataType::File => Links::File(PbLinks::new(&self.outer)),
            DataType::Symlink => Links::Symlink(PbLinks::new(&self.outer)),
            DataType::HamtShard => Links::HamtShard(PbLinks::new(&self.outer)),
            DataType::Metadata => unimplemented!(),
        }
    }

    /// Returns the hash type. Only used for HAMT Shards.
    pub fn hash_type(&self) -> Option<HamtHashFunction> {
        self.inner.hash_type.and_then(|t| t.try_into().ok())
    }

    /// Returns the fanout value. Only used for HAMT Shards.
    pub fn fanout(&self) -> Option<u32> {
        self.inner.fanout.and_then(|f| u32::try_from(f).ok())
    }
}

impl UnixfsNode {
    pub fn decode(cid: &Cid, buf: Bytes) -> Result<Self> {
        match cid.codec() {
            c if c == Codec::Raw as u64 => Ok(UnixfsNode::Raw(buf)),
            _ => {
                let outer = dag_pb::PbNode::decode(buf)?;
                let inner_data = outer
                    .data
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| anyhow!("missing data"))?;
                let inner = unixfs_pb::Data::decode(inner_data)?;
                let typ: DataType = inner.r#type.try_into()?;
                let node = Node { outer, inner };

                // ensure correct unixfs type
                match typ {
                    DataType::Raw => todo!(),
                    DataType::Directory => Ok(UnixfsNode::Directory(node)),
                    DataType::File => Ok(UnixfsNode::File(node)),
                    DataType::Symlink => Ok(UnixfsNode::Symlink(node)),
                    DataType::HamtShard => {
                        let hamt = Hamt::from_node(&node)?;
                        Ok(UnixfsNode::HamtShard(node, hamt))
                    }
                    DataType::Metadata => bail!("unixfs metadata is not supported"),
                }
            }
        }
    }

    pub fn encode(&self) -> Result<(Cid, Bytes)> {
        let (cid, out) = match self {
            UnixfsNode::Raw(data) => {
                let out = data.clone();
                let cid = Cid::new_v1(Codec::Raw as _, cid::multihash::Code::Sha2_256.digest(&out));
                (cid, out)
            }
            UnixfsNode::RawNode(node)
            | UnixfsNode::Directory(node)
            | UnixfsNode::File(node)
            | UnixfsNode::Symlink(node)
            | UnixfsNode::HamtShard(node, _) => {
                let out = node.encode()?;
                let cid = Cid::new_v1(
                    Codec::DagPb as _,
                    cid::multihash::Code::Sha2_256.digest(&out),
                );
                (cid, out)
            }
        };

        ensure!(
            out.len() <= DEFAULT_CHUNK_SIZE_LIMIT,
            "node is too large: {} bytes",
            out.len()
        );

        Ok((cid, out))
    }

    pub const fn typ(&self) -> Option<DataType> {
        match self {
            UnixfsNode::Raw(_) => None,
            UnixfsNode::RawNode(_) => Some(DataType::Raw),
            UnixfsNode::Directory(_) => Some(DataType::Directory),
            UnixfsNode::File(_) => Some(DataType::File),
            UnixfsNode::Symlink(_) => Some(DataType::Symlink),
            UnixfsNode::HamtShard(_, _) => Some(DataType::HamtShard),
        }
    }

    /// Returns the size in bytes of the underlying data.
    /// Available only for `Raw` and `File` which are a single block with no links.
    pub fn size(&self) -> Option<usize> {
        match self {
            UnixfsNode::Raw(data) => Some(data.len()),
            UnixfsNode::Directory(node)
            | UnixfsNode::RawNode(node)
            | UnixfsNode::File(node)
            | UnixfsNode::Symlink(node)
            | UnixfsNode::HamtShard(node, _) => node.size(),
        }
    }

    /// Returns the filesize in bytes.
    /// Should only be set for `Raw` and `File`.
    pub fn filesize(&self) -> Option<u64> {
        match self {
            UnixfsNode::Raw(data) => Some(data.len() as u64),
            UnixfsNode::Directory(node)
            | UnixfsNode::RawNode(node)
            | UnixfsNode::File(node)
            | UnixfsNode::Symlink(node)
            | UnixfsNode::HamtShard(node, _) => node.filesize(),
        }
    }

    pub fn links(&self) -> Links<'_> {
        match self {
            UnixfsNode::Raw(_) => Links::Raw,
            UnixfsNode::RawNode(node) => Links::RawNode(PbLinks::new(&node.outer)),
            UnixfsNode::Directory(node) => Links::Directory(PbLinks::new(&node.outer)),
            UnixfsNode::File(node) => Links::File(PbLinks::new(&node.outer)),
            UnixfsNode::Symlink(node) => Links::Symlink(PbLinks::new(&node.outer)),
            UnixfsNode::HamtShard(node, _) => Links::HamtShard(PbLinks::new(&node.outer)),
        }
    }

    pub fn links_owned(&self) -> Result<VecDeque<Link>> {
        self.links().map(|l| l.map(|l| l.to_owned())).collect()
    }

    pub const fn is_dir(&self) -> bool {
        matches!(self, Self::Directory(_) | Self::HamtShard(_, _))
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

    pub fn symlink(&self) -> Result<Option<&str>> {
        if let Self::Symlink(ref node) = self {
            let link = std::str::from_utf8(node.inner.data.as_deref().unwrap_or_default())?;
            Ok(Some(link))
        } else {
            Ok(None)
        }
    }

    /// If this is a directory or hamt shard, returns a stream that yields all children of it.
    pub fn as_child_reader<'a, 'b: 'a, T: ContentLoader>(
        &'a self,
        loader: &'b Resolver<T>,
        om: OutMetrics,
    ) -> Result<Option<UnixfsChildStream<'a>>> {
        match self {
            UnixfsNode::Raw(_)
            | UnixfsNode::RawNode(_)
            | UnixfsNode::File(_)
            | UnixfsNode::Symlink(_) => Ok(None),
            UnixfsNode::Directory(_) => {
                let source = self.links().map(|l| l.map(|l| l.to_owned()));
                let stream = futures::stream::iter(source).boxed();

                Ok(Some(UnixfsChildStream::Directory {
                    stream,
                    out_metrics: om,
                }))
            }
            UnixfsNode::HamtShard(_, hamt) => Ok(Some(UnixfsChildStream::Hamt {
                stream: hamt.children(loader).boxed(),
                pos: 0,
                out_metrics: om,
            })),
        }
    }

    pub fn into_content_reader<T: ContentLoader>(
        self,
        loader: Resolver<T>,
        om: OutMetrics,
    ) -> Result<Option<UnixfsContentReader<T>>> {
        match self {
            UnixfsNode::Raw(_)
            | UnixfsNode::RawNode(_)
            | UnixfsNode::File(_)
            | UnixfsNode::Symlink(_) => {
                let current_links = vec![self.links_owned()?];

                Ok(Some(UnixfsContentReader::File {
                    root_node: self,
                    pos: 0,
                    current_node: CurrentNodeState::Outer,
                    current_links,
                    loader,
                    out_metrics: om,
                    ctx: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
                }))
            }
            UnixfsNode::HamtShard(_, _) | UnixfsNode::Directory(_) => Ok(None),
        }
    }
}

pub enum UnixfsChildStream<'a> {
    Hamt {
        stream: BoxStream<'a, Result<Link>>,
        pos: usize,
        out_metrics: OutMetrics,
    },
    Directory {
        stream: BoxStream<'a, Result<Link>>,
        out_metrics: OutMetrics,
    },
}

pub enum UnixfsContentReader<T: ContentLoader> {
    File {
        root_node: UnixfsNode,
        /// Absolute position in bytes
        pos: usize,
        /// Current node being operated on, only used for nested nodes (not the root).
        current_node: CurrentNodeState,
        /// Stack of links left to traverse.
        current_links: Vec<VecDeque<Link>>,
        loader: Resolver<T>,
        out_metrics: OutMetrics,
        ctx: std::sync::Arc<tokio::sync::Mutex<Option<LoaderContext>>>,
    },
}

impl<T: ContentLoader> UnixfsContentReader<T> {
    /// Returns the size in bytes, if known in advance.
    pub fn size(&self) -> Option<u64> {
        match self {
            UnixfsContentReader::File { root_node, .. } => {
                // File size is stored in the protobuf
                root_node.filesize()
            }
        }
    }
}

impl Stream for UnixfsChildStream<'_> {
    type Item = Result<Link>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match &mut *self {
            UnixfsChildStream::Hamt { stream, .. } => Pin::new(stream).poll_next(cx),
            UnixfsChildStream::Directory { stream, .. } => Pin::new(stream).poll_next(cx),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            UnixfsChildStream::Directory { stream, .. } => stream.size_hint(),
            UnixfsChildStream::Hamt { .. } => (0, None),
        }
    }
}

impl<T: ContentLoader + Unpin + 'static> AsyncRead for UnixfsContentReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            UnixfsContentReader::File {
                root_node,
                pos,
                current_node,
                current_links,
                loader,
                out_metrics,
                ctx,
            } => {
                let typ = root_node.typ();
                let pos_current = *pos;
                let poll_res = match root_node {
                    UnixfsNode::Raw(data) => {
                        let res = poll_read_buf_at_pos(pos, data, buf);
                        Poll::Ready(res)
                    }
                    UnixfsNode::File(node) => poll_read_file_at(
                        cx,
                        node,
                        loader.loader().clone(),
                        pos,
                        buf,
                        current_links,
                        current_node,
                        ctx.clone(),
                    ),
                    UnixfsNode::Symlink(node) => {
                        let data = node.inner.data.as_deref().unwrap_or_default();
                        let res = poll_read_buf_at_pos(pos, data, buf);
                        Poll::Ready(res)
                    }
                    _ => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unsupported Unixfs type for file types: {:?} ", typ),
                    ))),
                };
                let bytes_read = *pos - pos_current;
                out_metrics.observe_bytes_read(pos_current, bytes_read);
                poll_res
            }
        }
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

#[allow(clippy::large_enum_variant)]
pub enum CurrentNodeState {
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
    current_links: &mut Vec<VecDeque<Link>>,
    loader: T,
    ctx: std::sync::Arc<tokio::sync::Mutex<Option<LoaderContext>>>,
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
        let mut ctx = ctx.lock().await;
        if ctx.is_none() {
            *ctx = Some(LoaderContext::from_path(Path::from_cid(link.cid)));
        }
        let mut ctx = ctx.as_mut().unwrap();
        let loaded_cid = loader.load_cid(&link.cid, &mut ctx).await?;
        let node = UnixfsNode::decode(&link.cid, loaded_cid.data)?;

        Ok(node)
    }
    .boxed();
    *current_node = CurrentNodeState::Loading(fut);
    false
}

#[allow(clippy::too_many_arguments)]
fn poll_read_file_at<T: ContentLoader + 'static>(
    cx: &mut Context<'_>,
    root_node: &Node,
    loader: T,
    pos: &mut usize,
    buf: &mut tokio::io::ReadBuf<'_>,
    current_links: &mut Vec<VecDeque<Link>>,
    current_node: &mut CurrentNodeState,
    ctx: std::sync::Arc<tokio::sync::Mutex<Option<LoaderContext>>>,
) -> Poll<std::io::Result<()>> {
    loop {
        match current_node {
            CurrentNodeState::Outer => {
                // check for links
                if root_node.outer.links.is_empty() {
                    // simplest case just one file
                    let data = root_node.inner.data.as_deref().unwrap_or(&[][..]);
                    let res = poll_read_buf_at_pos(pos, data, buf);
                    return Poll::Ready(res);
                }

                // read root local data
                if let Some(ref data) = root_node.inner.data {
                    if *pos < data.len() {
                        let res = poll_read_buf_at_pos(pos, data, buf);
                        return Poll::Ready(res);
                    }
                }
                *current_node = CurrentNodeState::None;
                if load_next_node(current_node, current_links, loader.clone(), ctx.clone()) {
                    return Poll::Ready(Ok(()));
                }
            }
            CurrentNodeState::None => {
                if load_next_node(current_node, current_links, loader.clone(), ctx.clone()) {
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
                        match node.links_owned() {
                            Ok(links) => {
                                current_links.push(links);
                                *current_node = CurrentNodeState::Loaded(0, node);
                            }
                            Err(e) => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    e.to_string(),
                                )));
                            }
                        }
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
                    UnixfsNode::Raw(data) => {
                        let old = *node_pos;
                        let res = poll_read_buf_at_pos(node_pos, data, buf);
                        // advance global pos
                        let amt_read = *node_pos - old;
                        *pos += amt_read;
                        if amt_read > 0 {
                            return Poll::Ready(res);
                        } else if *node_pos == data.len() {
                            // finished reading this node
                            if load_next_node(
                                current_node,
                                current_links,
                                loader.clone(),
                                ctx.clone(),
                            ) {
                                return Poll::Ready(Ok(()));
                            }
                        }
                    }
                    UnixfsNode::File(node) | UnixfsNode::RawNode(node) => {
                        // read direct node data
                        if let Some(ref data) = node.inner.data {
                            let old = *node_pos;
                            let res = poll_read_buf_at_pos(node_pos, data, buf);
                            let amt_read = *node_pos - old;
                            *pos += amt_read;
                            if amt_read > 0 {
                                return Poll::Ready(res);
                            }
                        }

                        // follow links
                        if load_next_node(current_node, current_links, loader.clone(), ctx.clone())
                        {
                            return Poll::Ready(Ok(()));
                        }
                    }
                    _ => {
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

#[derive(Debug)]
pub enum Links<'a> {
    Raw,
    RawNode(PbLinks<'a>),
    Directory(PbLinks<'a>),
    File(PbLinks<'a>),
    Symlink(PbLinks<'a>),
    HamtShard(PbLinks<'a>),
}

#[derive(Debug)]
pub struct PbLinks<'a> {
    i: usize,
    outer: &'a dag_pb::PbNode,
}

impl<'a> PbLinks<'a> {
    pub fn new(outer: &'a dag_pb::PbNode) -> Self {
        PbLinks { i: 0, outer }
    }
}

impl<'a> Iterator for Links<'a> {
    type Item = Result<LinkRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Links::Raw => None,
            Links::Directory(links)
            | Links::RawNode(links)
            | Links::File(links)
            | Links::Symlink(links)
            | Links::HamtShard(links) => links.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Links::Raw => (0, Some(0)),
            Links::Directory(links)
            | Links::RawNode(links)
            | Links::File(links)
            | Links::Symlink(links)
            | Links::HamtShard(links) => links.size_hint(),
        }
    }
}

impl<'a> Iterator for PbLinks<'a> {
    type Item = Result<LinkRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i == self.outer.links.len() {
            return None;
        }

        let l = &self.outer.links[self.i];
        self.i += 1;

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

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.outer.links.len(), Some(self.outer.links.len()))
    }
}
