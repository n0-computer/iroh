use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
    time::Instant,
};

use anyhow::{anyhow, Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;

use iroh_metrics::{
    core::{MObserver, MRecorder},
    gateway::{GatewayHistograms, GatewayMetrics},
    observe, record,
};
use libipld::Ipld;

use crate::{content_loader::LoaderContext, util::parse_links};

#[derive(Debug)]
pub struct LoadedCid {
    pub data: Bytes,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Bitswap,
    Http(String),
    Store(&'static str),
}

/// Represents an ipfs path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    typ: PathType,
    root: CidOrDomain,
    tail: Vec<String>,
}

impl Path {
    pub fn from_cid(cid: Cid) -> Self {
        Path {
            typ: PathType::Ipfs,
            root: CidOrDomain::Cid(cid),
            tail: Vec::new(),
        }
    }

    pub fn typ(&self) -> PathType {
        self.typ
    }

    pub fn root(&self) -> &CidOrDomain {
        &self.root
    }

    pub fn tail(&self) -> &[String] {
        &self.tail
    }

    // used only for string path manipulation
    pub fn has_trailing_slash(&self) -> bool {
        !self.tail.is_empty() && self.tail.last().unwrap().is_empty()
    }

    pub fn push(&mut self, str: impl AsRef<str>) {
        self.tail.push(str.as_ref().to_owned());
    }

    // Empty path segments in the *middle* shouldn't occur,
    // though they can occur at the end, which `join` handles.
    // TODO(faassen): it would make sense to return a `RelativePathBuf` here at some
    // point in the future so we don't deal with bare strings anymore and
    // we're forced to handle various cases more explicitly.
    pub fn to_relative_string(&self) -> String {
        self.tail.join("/")
    }

    pub fn cid(&self) -> Option<&Cid> {
        match &self.root {
            CidOrDomain::Cid(cid) => Some(cid),
            CidOrDomain::Domain(_) => None,
        }
    }
}

/// Holds information if we should clip the response and to what offset
#[derive(Debug, Clone, Copy)]
pub enum ResponseClip {
    NoClip,
    Clip(usize),
}

impl From<usize> for ResponseClip {
    fn from(item: usize) -> Self {
        if item == 0 {
            ResponseClip::NoClip
        } else {
            ResponseClip::Clip(item)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidOrDomain {
    Cid(Cid),
    Domain(String),
}

impl Display for CidOrDomain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CidOrDomain::Cid(c) => Display::fmt(&c, f),
            CidOrDomain::Domain(s) => Display::fmt(&s, f),
        }
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "/{}/{}", self.typ.as_str(), self.root)?;

        for part in &self.tail {
            if part.is_empty() {
                continue;
            }
            write!(f, "/{}", part)?;
        }

        if self.has_trailing_slash() {
            write!(f, "/")?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathType {
    /// `/ipfs`
    Ipfs,
    /// `/ipns`
    Ipns,
}

impl PathType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PathType::Ipfs => "ipfs",
            PathType::Ipns => "ipns",
        }
    }
}

impl FromStr for Path {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(&['/', '\\']).filter(|s| !s.is_empty());

        let first_part = parts.next().ok_or_else(|| anyhow!("path too short"))?;
        let (typ, root) = if first_part.eq_ignore_ascii_case("ipns") {
            let root = parts.next().ok_or_else(|| anyhow!("path too short"))?;
            let root = if let Ok(c) = Cid::from_str(root) {
                CidOrDomain::Cid(c)
            } else {
                // TODO: url validation?
                CidOrDomain::Domain(root.to_string())
            };

            (PathType::Ipns, root)
        } else {
            let root = if first_part.eq_ignore_ascii_case("ipfs") {
                parts.next().ok_or_else(|| anyhow!("path too short"))?
            } else {
                first_part
            };

            let root = Cid::from_str(root).context("invalid cid")?;

            (PathType::Ipfs, CidOrDomain::Cid(root))
        };

        let mut tail: Vec<String> = parts.map(Into::into).collect();

        if s.ends_with('/') {
            tail.push("".to_owned());
        }

        Ok(Path { typ, root, tail })
    }
}

#[async_trait]
pub trait LinksContainer: Sync + Send + std::fmt::Debug + Clone + 'static {
    /// Extract links out of a container struct.
    fn links(&self) -> Result<Vec<Cid>>;
}

#[async_trait]
impl LinksContainer for OutRaw {
    fn links(&self) -> Result<Vec<Cid>> {
        parse_links(&self.cid, &self.content)
    }
}

#[async_trait]
impl LinksContainer for Out {
    fn links(&self) -> Result<Vec<Cid>> {
        Out::links(self)
    }
}

#[derive(Debug, Clone)]
pub struct OutRaw {
    source: Source,
    content: Bytes,
    cid: Cid,
}

impl OutRaw {
    pub fn from_loaded(cid: Cid, loaded: LoadedCid) -> Self {
        Self {
            source: loaded.source,
            content: loaded.data,
            cid,
        }
    }
    pub fn source(&self) -> &Source {
        &self.source
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn content(&self) -> &Bytes {
        &self.content
    }
}

#[derive(Debug, Clone)]
pub struct Out {
    metadata: Metadata,
    pub(crate) content: OutContent,
    context: LoaderContext,
}

impl Out {
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Is this content mutable?
    ///
    /// Returns `true` if the underlying root is an IPNS entry.
    pub fn is_mutable(&self) -> bool {
        matches!(self.metadata.path.typ, PathType::Ipns)
    }

    pub fn is_dir(&self) -> bool {
        match &self.content {
            OutContent::Unixfs(node) => node.is_dir(),
            _ => false,
        }
    }

    pub fn is_symlink(&self) -> bool {
        self.metadata.unixfs_type == Some(UnixfsType::Symlink)
    }

    /// What kind of content this is this.
    pub fn typ(&self) -> OutType {
        self.content.typ()
    }

    pub fn links(&self) -> Result<Vec<Cid>> {
        self.content.links()
    }

    /// Returns links with an associated file or directory name if the content
    /// is unixfs
    pub fn named_links(&self) -> Result<Vec<(Option<&str>, Cid)>> {
        match &self.content {
            // TODO(ramfox): add back in when we figure out circular dependencies
            // OutContent::Unixfs(node) => node.links().map(|l| l.map(|l| (l.name, l.cid))).collect(),
            OutContent::Unixfs(_) => todo!(),
            _ => {
                let links = self.content.links();
                links.map(|l| l.into_iter().map(|l| (None, l)).collect())
            }
        }
    }

    // TODO(ramfox): figure out circular dependencies
    //     /// Returns a stream over the content of this directory.
    //     /// Only if this is of type `unixfs` and a directory.
    //     pub fn unixfs_read_dir<'a, 'b: 'a, C: ContentLoader>(
    //         &'a self,
    //         loader: &'b Resolver<C>,
    //         om: OutMetrics,
    //     ) -> Result<Option<UnixfsChildStream<'a>>> {
    //         match &self.content {
    //             OutContent::Unixfs(node) => node.as_child_reader(self.context.clone(), loader, om),
    //             _ => Ok(None),
    //         }
    //     }

    //     pub fn pretty<T: ContentLoader>(
    //         self,
    //         loader: Resolver<T>,
    //         om: OutMetrics,
    //         clip: ResponseClip,
    //     ) -> Result<OutPrettyReader<T>> {
    //         let pos = 0;
    //         match self.content {
    //             OutContent::DagPb(_, mut bytes) => {
    //                 if let ResponseClip::Clip(n) = clip {
    //                     bytes.truncate(n);
    //                 }
    //                 Ok(OutPrettyReader::DagPb(BytesReader { pos, bytes, om }))
    //             }
    //             OutContent::DagCbor(_, mut bytes) => {
    //                 if let ResponseClip::Clip(n) = clip {
    //                     bytes.truncate(n);
    //                 }
    //                 Ok(OutPrettyReader::DagCbor(BytesReader { pos, bytes, om }))
    //             }
    //             OutContent::DagJson(_, mut bytes) => {
    //                 if let ResponseClip::Clip(n) = clip {
    //                     bytes.truncate(n);
    //                 }
    //                 Ok(OutPrettyReader::DagJson(BytesReader { pos, bytes, om }))
    //             }
    //             OutContent::Raw(_, mut bytes) => {
    //                 if let ResponseClip::Clip(n) = clip {
    //                     bytes.truncate(n);
    //                 }
    //                 Ok(OutPrettyReader::Raw(BytesReader { pos, bytes, om }))
    //             }
    //             OutContent::Unixfs(node) => {
    //                 let ctx = self.context;
    //                 let reader = node
    //                     .into_content_reader(ctx, loader, om, clip)?
    //                     .ok_or_else(|| anyhow!("cannot read the contents of a directory"))?;

    //                 Ok(OutPrettyReader::Unixfs(reader))
    //             }
    //         }
    //     }
}

#[derive(Debug, Clone)]
pub(crate) enum OutContent {
    DagPb(Ipld, Bytes),
    Unixfs(UnixfsNode),
    DagCbor(Ipld, Bytes),
    DagJson(Ipld, Bytes),
    Raw(Ipld, Bytes),
}

impl OutContent {
    pub(crate) fn typ(&self) -> OutType {
        match self {
            OutContent::DagPb(_, _) => OutType::DagPb,
            OutContent::Unixfs(_) => OutType::Unixfs,
            OutContent::DagCbor(_, _) => OutType::DagCbor,
            OutContent::DagJson(_, _) => OutType::DagJson,
            OutContent::Raw(_, _) => OutType::Raw,
        }
    }

    pub(crate) fn links(&self) -> Result<Vec<Cid>> {
        match self {
            OutContent::DagPb(ipld, _)
            | OutContent::DagCbor(ipld, _)
            | OutContent::DagJson(ipld, _)
            | OutContent::Raw(ipld, _) => {
                let mut links = Vec::new();
                ipld.references(&mut links);
                Ok(links)
            }
            // TODO(ramfox): add back in when we figure out circular dependencies
            // OutContent::Unixfs(node) => node.links().map(|r| r.map(|r| r.cid)).collect(),
            OutContent::Unixfs(_node) => todo!(),
        }
    }
}

/// Metadata for the reolution result.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// The original path for that was resolved.
    pub path: Path,
    /// Size in bytes.
    pub size: Option<u64>,
    pub typ: OutType,
    pub unixfs_type: Option<UnixfsType>,
    /// List of resolved cids. In order of the `path`.
    ///
    /// Only contains the "top level cids", and only path segments that actually map
    /// to a block.
    pub resolved_path: Vec<Cid>,
    pub source: Source,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OutType {
    DagPb,
    Unixfs,
    DagCbor,
    DagJson,
    Raw,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UnixfsType {
    Dir,
    File,
    Symlink,
}

pub struct OutMetrics {
    pub start: Instant,
}

impl OutMetrics {
    pub fn observe_bytes_read(&self, pos: usize, bytes_read: usize) {
        if pos == 0 && bytes_read > 0 {
            record!(
                GatewayMetrics::TimeToServeFirstBlock,
                self.start.elapsed().as_millis() as u64
            );
        }
        if bytes_read == 0 {
            record!(
                GatewayMetrics::TimeToServeFullFile,
                self.start.elapsed().as_millis() as u64
            );
            observe!(
                GatewayHistograms::TimeToServeFullFile,
                self.start.elapsed().as_millis() as f64
            );
        }
        record!(GatewayMetrics::BytesStreamed, bytes_read as u64);
    }
}

impl Default for OutMetrics {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

// TODO(ramfox): use actual UnixfsNode impl
#[derive(Debug, PartialEq, Clone)]
pub enum UnixfsNode {
    Raw(Bytes),
    RawNode(Node),
    Directory(Node),
    File(Node),
    Symlink(Node),
    HamtShard(Node, Hamt),
}

impl UnixfsNode {
    pub fn is_dir(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Node {}

#[derive(Debug, PartialEq, Clone)]
pub struct Hamt {}
