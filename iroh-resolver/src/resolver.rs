use std::collections::VecDeque;
use std::fmt::{self, Debug, Display, Formatter};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use futures::{Future, Stream, TryStreamExt};
use iroh_metrics::inc;
use iroh_unixfs::{
    codecs::Codec,
    content_loader::{ContentLoader, ContextId, LoaderContext},
    parse_links,
    unixfs::{read_data_to_buf, DataType, UnixfsChildStream, UnixfsContentReader, UnixfsNode},
    Block, Link, LoadedCid, Source,
};
use libipld::codec::Encode;
use libipld::prelude::Codec as _;
use libipld::{Ipld, IpldCodec};
use tokio::io::{AsyncRead, AsyncSeek};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use iroh_metrics::{
    core::MRecorder,
    resolver::{OutMetrics, ResolverMetrics},
};

use crate::dns_resolver::{Config, DnsResolver};

pub const IROH_STORE: &str = "iroh-store";

// ToDo: Remove this function
// Related issue: https://github.com/n0-computer/iroh/issues/593
fn from_peer_id(id: &str) -> Option<libipld::Multihash> {
    static MAX_INLINE_KEY_LENGTH: usize = 42;
    let multihash =
        libp2p::multihash::Multihash::from_bytes(&bs58::decode(id).into_vec().ok()?).ok()?;
    match libp2p::multihash::Code::try_from(multihash.code()) {
        Ok(libp2p::multihash::Code::Sha2_256) => {
            Some(libipld::Multihash::from_bytes(&multihash.to_bytes()).unwrap())
        }
        Ok(libp2p::multihash::Code::Identity)
            if multihash.digest().len() <= MAX_INLINE_KEY_LENGTH =>
        {
            Some(libipld::Multihash::from_bytes(&multihash.to_bytes()).unwrap())
        }
        _ => None,
    }
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

    pub fn from_parts(
        scheme: &str,
        cid_or_domain: &str,
        tail_path: &str,
    ) -> Result<Self, anyhow::Error> {
        let (typ, root) = if scheme.eq_ignore_ascii_case("ipns") {
            let root = if let Ok(cid) = Cid::from_str(cid_or_domain) {
                CidOrDomain::Cid(cid)
            } else if let Some(multihash) = from_peer_id(cid_or_domain) {
                CidOrDomain::Cid(Cid::new_v1(Codec::Libp2pKey.into(), multihash))
            // ToDo: Bring back commented "else if" instead of "else if" above
            // Related issue: https://github.com/n0-computer/iroh/issues/593
            // } else if let Ok(peer_id) = PeerId::from_str(cid_or_domain) {
            //    CidOrDomain::Cid(Cid::new_v1(Codec::Libp2pKey.into(), *peer_id.as_ref()))
            } else {
                CidOrDomain::Domain(cid_or_domain.to_string())
            };
            (PathType::Ipns, root)
        } else {
            let root = Cid::from_str(cid_or_domain).context("invalid cid")?;
            (PathType::Ipfs, CidOrDomain::Cid(root))
        };
        let mut tail = tail_path
            .split(&['/', '\\'])
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect::<Vec<_>>();
        if tail_path.ends_with('/') {
            tail.push("".to_string())
        }
        Ok(Path { typ, root, tail })
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

    pub fn with_suffix(&self, suffix: impl AsRef<str>) -> Self {
        let mut suffixed = self.clone();
        suffixed.push(suffix);
        suffixed
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

impl Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "/{}/{}", self.typ.as_str(), self.root)?;

        for part in &self.tail {
            if part.is_empty() {
                continue;
            }
            write!(f, "/{part}")?;
        }

        if self.has_trailing_slash() {
            write!(f, "/")?;
        }

        Ok(())
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

    // ToDo: Replace it with from_parts (or vice verse)
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
    pub content: OutContent,
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
        matches!(self.metadata.path.typ(), PathType::Ipns)
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
            OutContent::Unixfs(node) => node.links().map(|l| l.map(|l| (l.name, l.cid))).collect(),
            _ => {
                let links = self.content.links();
                links.map(|l| l.into_iter().map(|l| (None, l)).collect())
            }
        }
    }

    /// Returns a stream over the content of this directory.
    /// Only if this is of type `unixfs` and a directory.
    pub fn unixfs_read_dir<'a, 'b: 'a, C: ContentLoader>(
        &'a self,
        loader: &'b Resolver<C>,
        om: OutMetrics,
    ) -> Result<Option<UnixfsChildStream<'a>>> {
        match &self.content {
            OutContent::Unixfs(node) => {
                node.as_child_reader(self.context.clone(), loader.loader().clone(), om)
            }
            _ => Ok(None),
        }
    }

    pub fn pretty<T: ContentLoader>(
        self,
        loader: Resolver<T>,
        om: OutMetrics,
        pos_max: Option<usize>,
    ) -> Result<OutPrettyReader<T>> {
        let pos = 0;
        match self.content {
            OutContent::DagPb(_, mut bytes) => {
                if let Some(pos_max) = pos_max {
                    bytes.truncate(pos_max);
                }
                Ok(OutPrettyReader::DagPb(BytesReader { pos, bytes, om }))
            }
            OutContent::DagCbor(_, mut bytes) => {
                if let Some(pos_max) = pos_max {
                    bytes.truncate(pos_max);
                }
                Ok(OutPrettyReader::DagCbor(BytesReader { pos, bytes, om }))
            }
            OutContent::DagJson(_, mut bytes) => {
                if let Some(pos_max) = pos_max {
                    bytes.truncate(pos_max);
                }
                Ok(OutPrettyReader::DagJson(BytesReader { pos, bytes, om }))
            }
            OutContent::Raw(_, mut bytes) => {
                if let Some(pos_max) = pos_max {
                    bytes.truncate(pos_max);
                }
                Ok(OutPrettyReader::Raw(BytesReader { pos, bytes, om }))
            }
            OutContent::Unixfs(node) => {
                let ctx = self.context;
                let reader = node
                    .into_content_reader(ctx, loader.loader().clone(), om, pos_max)?
                    .ok_or_else(|| anyhow!("cannot read the contents of a directory"))?;

                Ok(OutPrettyReader::Unixfs(reader))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum OutContent {
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
            OutContent::Unixfs(node) => node.links().map(|r| r.map(|r| r.cid)).collect(),
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

pub enum OutPrettyReader<C: ContentLoader> {
    DagPb(BytesReader),
    Unixfs(UnixfsContentReader<C>),
    DagCbor(BytesReader),
    DagJson(BytesReader),
    Raw(BytesReader),
}

impl<T: ContentLoader> Debug for OutPrettyReader<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            OutPrettyReader::DagPb(_) => write!(f, "OutPrettyReader::DabPb"),
            OutPrettyReader::Unixfs(_) => write!(f, "OutPrettyReader::Unixfs"),
            OutPrettyReader::DagCbor(_) => write!(f, "OutPrettyReader::DagCbor"),
            OutPrettyReader::DagJson(_) => write!(f, "OutPrettyReader::DagJson"),
            OutPrettyReader::Raw(_) => write!(f, "OutPrettyReader::Raw"),
        }
    }
}

impl<T: ContentLoader> OutPrettyReader<T> {
    /// Returns the size in bytes, if known in advance.
    pub fn size(&self) -> Option<u64> {
        match self {
            OutPrettyReader::DagPb(reader)
            | OutPrettyReader::DagCbor(reader)
            | OutPrettyReader::DagJson(reader)
            | OutPrettyReader::Raw(reader) => reader.size(),
            OutPrettyReader::Unixfs(reader) => reader.size(),
        }
    }
}

#[derive(Debug)]
pub struct BytesReader {
    pos: usize,
    bytes: Bytes,
    om: OutMetrics,
}

impl BytesReader {
    /// Returns the size in bytes, if known in advance.
    pub fn size(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

impl<T: ContentLoader + Unpin + 'static> AsyncRead for OutPrettyReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            OutPrettyReader::DagPb(bytes_reader)
            | OutPrettyReader::DagCbor(bytes_reader)
            | OutPrettyReader::DagJson(bytes_reader)
            | OutPrettyReader::Raw(bytes_reader) => {
                let pos_current = bytes_reader.pos;
                let bytes_read = read_data_to_buf(
                    &mut bytes_reader.pos,
                    Some(bytes_reader.bytes.len()),
                    &bytes_reader.bytes[pos_current..],
                    buf,
                );
                bytes_reader.om.observe_bytes_read(pos_current, bytes_read);
                Poll::Ready(Ok(()))
            }
            OutPrettyReader::Unixfs(r) => Pin::new(&mut *r).poll_read(cx, buf),
        }
    }
}

impl<T: ContentLoader + Unpin + 'static> AsyncSeek for OutPrettyReader<T> {
    fn start_seek(mut self: Pin<&mut Self>, position: std::io::SeekFrom) -> std::io::Result<()> {
        match &mut *self {
            OutPrettyReader::DagPb(bytes_reader)
            | OutPrettyReader::DagCbor(bytes_reader)
            | OutPrettyReader::DagJson(bytes_reader)
            | OutPrettyReader::Raw(bytes_reader) => {
                let pos_current = bytes_reader.pos as i64;
                let data_len = bytes_reader.bytes.len();
                if data_len == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cannot seek on empty data",
                    ));
                }
                match position {
                    std::io::SeekFrom::Start(pos) => {
                        let i = std::cmp::min(data_len - 1, pos as usize);
                        bytes_reader.pos = i;
                    }
                    std::io::SeekFrom::End(pos) => {
                        let mut i = (data_len as i64 + pos) % data_len as i64;
                        if i < 0 {
                            i += data_len as i64;
                        }
                        bytes_reader.pos = i as usize;
                    }
                    std::io::SeekFrom::Current(pos) => {
                        let mut i = std::cmp::min(data_len as i64 - 1, pos_current + pos);
                        i = std::cmp::max(0, i);
                        bytes_reader.pos = i as usize;
                    }
                }
                Ok(())
            }
            OutPrettyReader::Unixfs(r) => Pin::new(&mut *r).start_seek(position),
        }
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<u64>> {
        match &mut *self {
            OutPrettyReader::DagPb(bytes_reader)
            | OutPrettyReader::DagCbor(bytes_reader)
            | OutPrettyReader::DagJson(bytes_reader)
            | OutPrettyReader::Raw(bytes_reader) => Poll::Ready(Ok(bytes_reader.pos as u64)),
            OutPrettyReader::Unixfs(r) => Pin::new(&mut *r).poll_complete(_cx),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Resolver<T: ContentLoader> {
    loader: T,
    dns_resolver: Arc<DnsResolver>,
    next_id: Arc<AtomicU64>,
    _worker: Arc<JoinHandle<()>>,
    session_closer: async_channel::Sender<ContextId>,
}

impl<T: ContentLoader> Resolver<T> {
    pub fn new(loader: T) -> Self {
        Self::with_dns_resolver(loader, Config::default())
    }

    pub fn with_dns_resolver(loader: T, dns_resolver_config: Config) -> Self {
        let (session_closer_s, session_closer_r) = async_channel::bounded(2048);
        let loader_thread = loader.clone();
        let worker = tokio::task::spawn(async move {
            // GC Loop for sessions
            while let Ok(session) = session_closer_r.recv().await {
                let loader = loader_thread.clone();

                tokio::task::spawn(async move {
                    debug!("stopping session {}", session);
                    if let Err(err) = loader.stop_session(session).await {
                        warn!("failed to stop session {}: {:?}", session, err);
                    }
                    debug!("stopping session {} done", session);
                });
            }
        });

        Resolver {
            loader,
            dns_resolver: Arc::new(DnsResolver::from_config(dns_resolver_config)),
            next_id: Arc::new(AtomicU64::new(0)),
            _worker: Arc::new(worker),
            session_closer: session_closer_s,
        }
    }

    fn next_id(&self) -> ContextId {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        ContextId(id)
    }

    pub fn loader(&self) -> &T {
        &self.loader
    }

    #[tracing::instrument(skip(self))]
    pub fn resolve_recursive_with_paths(
        &self,
        root: Path,
    ) -> impl Stream<Item = Result<(Path, Out)>> {
        let mut blocks = VecDeque::new();
        let this = self.clone();
        async_stream::try_stream! {
            let output_path = root.clone();
            blocks.push_back((output_path, this.resolve(root).await));
            loop {
                if let Some((current_output_path, current_out)) = blocks.pop_front() {
                    let current = current_out?;
                    if !current.is_dir() {
                        yield (current_output_path, current);
                        continue
                    }

                    // TODO(ramfox): we may want to just keep the stream and iterate over the links
                    // that way, rather than gathering and then chunking again
                    let links: Result<Vec<Link>> = current
                        .unixfs_read_dir(&this, OutMetrics::default())?
                        .expect("already know this is a directory")
                        .try_collect()
                        .await;
                    let links = links?;
                    // TODO: configurable limit
                    for link_chunk in links.chunks(8) {
                        let next = futures::future::join_all(
                            link_chunk.iter().map(|link| {
                                let this = this.clone();
                                let mut this_path = current_output_path.clone();
                                let name = link.name.clone();
                                match name {
                                    None => this_path.push(link.cid.to_string()),
                                    Some(p) =>  this_path.push(p),
                                };
                                async move {
                                    (this_path, this.resolve(Path::from_cid(link.cid)).await)
                                }
                            })
                        ).await;
                        for res in next.into_iter() {
                            blocks.push_back(res);
                        }
                    }
                    yield (current_output_path, current);
                } else {
                    // no links left to resolve
                    break;
                }
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn resolve_recursive(&self, root: Path) -> impl Stream<Item = Result<Out>> {
        let this = self.clone();
        self.resolve_recursive_mapped(root, None, move |cid, ctx| {
            let this = this.clone();
            async move { this.resolve_with_ctx(ctx, Path::from_cid(cid), false).await }
        })
    }

    /// Resolve a path recursively and yield the raw bytes plus metadata.
    #[tracing::instrument(skip(self))]
    pub fn resolve_recursive_raw(
        &self,
        root: Path,
        recursion_limit: Option<usize>,
    ) -> impl Stream<Item = Result<OutRaw>> {
        let this = self.clone();
        self.resolve_recursive_mapped(root, recursion_limit, move |cid, mut ctx| {
            let this = this.clone();
            async move {
                this.load_cid(&cid, &mut ctx)
                    .await
                    .map(|loaded| OutRaw::from_loaded(cid, loaded))
            }
        })
    }

    /// Resolve a path recursively and supply a closure to resolve cids to outputs.
    #[tracing::instrument(skip(self, resolve))]
    pub fn resolve_recursive_mapped<O, M, F>(
        &self,
        root: Path,
        recursion_limit: Option<usize>,
        resolve: M,
    ) -> impl Stream<Item = Result<O>>
    where
        O: LinksContainer,
        M: Fn(Cid, LoaderContext) -> F + Clone,
        F: Future<Output = Result<O>> + Send + 'static,
    {
        let mut ctx = LoaderContext::from_path(self.next_id(), self.session_closer.clone());

        let mut cids = VecDeque::new();
        let this = self.clone();
        let mut counter = 0;
        let chunk_size = 8;
        async_stream::try_stream! {
            let root_cid = this.resolve_path_to_cid(&root, &mut ctx).await?;
            let root_block = resolve(root_cid, ctx.clone()).await?;
            cids.push_back(root_block);
            loop {
                if let Some(current) = cids.pop_front() {
                    let links = current.links()?;
                    counter += links.len();
                    if let Some(limit) = recursion_limit {
                        if counter > limit {
                            Err(anyhow::anyhow!("Number of links exceeds the recursion limit."))?;
                        }
                    }

                    // TODO: configurable limit
                    for link_chunk in links.chunks(chunk_size) {
                        let next = futures::future::join_all(
                            link_chunk.iter().map(|link| {
                                let resolve = resolve.clone();
                                let ctx = ctx.clone();
                                async move {
                                    resolve(*link, ctx).await
                                }
                            })
                        ).await;
                        for res in next.into_iter() {
                            let res = res?;
                            cids.push_back(res);
                        }
                    }
                    yield current;

                } else {
                    // no links left to resolve
                    break;
                }
            }
        }
    }

    /// Resolves through a given path, returning the [`Cid`] and raw bytes of the final leaf.
    #[tracing::instrument(skip(self))]
    pub async fn resolve(&self, path: Path) -> Result<Out> {
        let ctx = LoaderContext::from_path(self.next_id(), self.session_closer.clone());

        self.resolve_with_ctx(ctx, path, false).await
    }

    /// Resolves through a given path, returning the [`Cid`] and raw bytes of the final leaf.
    /// Forces the RAW codec.
    #[tracing::instrument(skip(self))]
    pub async fn resolve_raw(&self, path: Path) -> Result<Out> {
        let ctx = LoaderContext::from_path(self.next_id(), self.session_closer.clone());

        self.resolve_with_ctx(ctx, path, true).await
    }

    pub async fn resolve_with_ctx(
        &self,
        mut ctx: LoaderContext,
        path: Path,
        force_raw: bool,
    ) -> Result<Out> {
        // Resolve the root block.
        let (root_cid, loaded_cid) = self.resolve_root(&path, &mut ctx).await?;
        match loaded_cid.source {
            Source::Store(_) => inc!(ResolverMetrics::CacheHit),
            _ => inc!(ResolverMetrics::CacheMiss),
        }

        let codec = match force_raw {
            true => Codec::Raw,
            false => Codec::try_from(root_cid.codec()).context("unknown codec")?,
        };

        match codec {
            Codec::DagPb => {
                self.resolve_dag_pb_or_unixfs(path, root_cid, loaded_cid, ctx)
                    .await
            }
            Codec::DagCbor | Codec::DagJson | Codec::Raw => {
                self.resolve_ipld(path, root_cid, loaded_cid, ctx).await
            }
            _ => bail!("unsupported codec {:?}", codec),
        }
    }

    // TODO(ramfox): when get the cid of the next link, we should
    // check the codec, and possibly resolve as ipld, allowing us to bridge
    // between unixfs & ipld data (going one way)
    async fn inner_resolve(
        &self,
        current: &mut UnixfsNode,
        resolved_path: &mut Vec<Cid>,
        part: &str,
        ctx: &mut LoaderContext,
    ) -> Result<()> {
        match current {
            UnixfsNode::Directory(_) => {
                let next_link = current
                    .get_link_by_name(&part)
                    .await?
                    .ok_or_else(|| anyhow!("UnixfsNode::Directory link '{}' not found", part))?;
                let loaded_cid = self.load_cid(&next_link.cid, ctx).await?;
                let next_node = UnixfsNode::decode(&next_link.cid, loaded_cid.data)?;
                resolved_path.push(next_link.cid);

                *current = next_node;
            }
            UnixfsNode::HamtShard(_, hamt) => {
                let (next_link, next_node) = hamt
                    .get(ctx.clone(), self.loader().clone(), part.as_bytes())
                    .await?
                    .ok_or_else(|| anyhow!("UnixfsNode::HamtShard link '{}' not found", part))?;
                // TODO: is this the right way to to resolved path here?
                resolved_path.push(next_link.cid);

                *current = next_node.clone();
            }
            _ => {
                bail!("unexpected unixfs type {:?}", current.typ());
            }
        }

        Ok(())
    }

    /// Resolves through both DagPb and nested UnixFs DAGs.
    #[tracing::instrument(skip(self, loaded_cid))]
    async fn resolve_dag_pb_or_unixfs(
        &self,
        root_path: Path,
        cid: Cid,
        loaded_cid: LoadedCid,
        mut ctx: LoaderContext,
    ) -> Result<Out> {
        trace!("{:?} resolving {} for {}", ctx.id(), cid, root_path);
        if let Ok(node) = UnixfsNode::decode(&cid, loaded_cid.data.clone()) {
            let tail = &root_path.tail();
            let mut current = node;
            let mut resolved_path = vec![cid];

            for part in tail.iter().filter(|s| !s.is_empty()) {
                self.inner_resolve(&mut current, &mut resolved_path, part, &mut ctx)
                    .await?;
            }

            let unixfs_type = match current.typ() {
                Some(DataType::Directory) => Some(UnixfsType::Dir),
                Some(DataType::HamtShard) => Some(UnixfsType::Dir),
                Some(DataType::File) | Some(DataType::Raw) => Some(UnixfsType::File),
                Some(DataType::Symlink) => Some(UnixfsType::Symlink),
                Some(DataType::Metadata) => None,
                None => {
                    // this means the file is raw
                    Some(UnixfsType::File)
                }
            };
            let metadata = Metadata {
                path: root_path,
                size: current.filesize(),
                typ: OutType::Unixfs,
                unixfs_type,
                resolved_path,
                source: loaded_cid.source,
            };
            Ok(Out {
                metadata,
                context: ctx,
                content: OutContent::Unixfs(current),
            })
        } else {
            self.resolve_ipld(root_path, cid, loaded_cid, ctx).await
        }
    }

    #[tracing::instrument(skip(self, loaded_cid))]
    async fn resolve_ipld(
        &self,
        root_path: Path,
        cid: Cid,
        loaded_cid: LoadedCid,
        mut ctx: LoaderContext,
    ) -> Result<Out> {
        trace!("{:?} resolving {} for {}", ctx.id(), cid, root_path);
        let codec: libipld::IpldCodec = cid.codec().try_into()?;
        let ipld: libipld::Ipld = codec
            .decode(&loaded_cid.data)
            .map_err(|e| anyhow!("invalid {:?}: {:?}", codec, e))?;

        let (codec, out) = self
            .resolve_ipld_path(cid, codec, ipld, root_path.tail(), &mut ctx)
            .await?;

        // reencode if we only return part of the original
        let bytes = if root_path.tail().is_empty() {
            loaded_cid.data
        } else {
            let mut bytes = Vec::new();
            out.encode(codec, &mut bytes)?;
            bytes.into()
        };

        let size = bytes.len() as u64;

        let (typ, content) = match codec {
            IpldCodec::Raw => (OutType::Raw, OutContent::Raw(out, bytes)),
            IpldCodec::DagCbor => (OutType::DagCbor, OutContent::DagCbor(out, bytes)),
            IpldCodec::DagJson => (OutType::DagJson, OutContent::DagJson(out, bytes)),
            IpldCodec::DagPb => (OutType::DagPb, OutContent::DagPb(out, bytes)),
        };

        let metadata = Metadata {
            path: root_path,
            size: Some(size),
            typ,
            unixfs_type: None,
            resolved_path: vec![cid],
            source: loaded_cid.source,
        };
        Ok(Out {
            metadata,
            context: ctx,
            content,
        })
    }

    #[tracing::instrument(skip(self, root))]
    async fn resolve_ipld_path(
        &self,
        _cid: Cid,
        codec: IpldCodec,
        root: Ipld,
        path: &[String],
        ctx: &mut LoaderContext,
    ) -> Result<(IpldCodec, Ipld)> {
        let mut current = root;
        let mut codec = codec;

        for part in path.iter().filter(|s| !s.is_empty()) {
            if let Ipld::Link(c) = current {
                (codec, current) = self.load_ipld_link(c, ctx).await?;
            }
            if codec == IpldCodec::DagPb {
                current = self.get_dagpb_link(current, part)?;
            } else {
                let index: libipld::ipld::IpldIndex = if let Ok(i) = part.parse::<usize>() {
                    i.into()
                } else {
                    part.clone().into()
                };
                current = current.take(index).map_err(|_| {
                    anyhow!(
                        "IPLD resolve error: Couldn't find part {} in path '{}'",
                        part,
                        path.join("/")
                    )
                })?;
            }
        }
        if let libipld::Ipld::Link(c) = current {
            (codec, current) = self.load_ipld_link(c, ctx).await?;
        }

        Ok((codec, current))
    }

    #[tracing::instrument(skip(self))]
    async fn load_ipld_link(&self, cid: Cid, ctx: &mut LoaderContext) -> Result<(IpldCodec, Ipld)> {
        let codec: IpldCodec = cid.codec().try_into()?;

        // resolve link and update if we have encountered a link
        let loaded_cid = self.load_cid(&cid, ctx).await?;

        let ipld: Ipld = codec
            .decode(&loaded_cid.data)
            .map_err(|e| anyhow!("invalid {:?}: {:?}", codec, e))?;
        Ok((codec, ipld))
    }

    #[tracing::instrument(skip(self, name))]
    fn get_dagpb_link<I: Into<String>>(&self, ipld: Ipld, name: I) -> Result<Ipld> {
        let name = name.into();
        let links = ipld
            .take("Links")
            .map_err(|_| anyhow!("Expected the DagPb node to have a list of links."))?;
        let mut links_iter = links.iter();

        // first iteration is the link list itself
        let _ = links_iter
            .next()
            .ok_or_else(|| anyhow!("expected DagPb links to exist"));

        for dagpb_link in links_iter {
            match dagpb_link
                .clone()
                .take("Name")
                .map_err(|_| anyhow!("Expected the Dagpb link to have a 'Name' field"))?
            {
                libipld::Ipld::String(n) => {
                    if n == name {
                        let link = dagpb_link.clone().take("Hash").map_err(|_| {
                            anyhow!("Expected the DagPb link to have a 'Hash' field")
                        })?;
                        return Ok(link);
                    }
                }
                _ => return Err(anyhow!("expected DagPb link to have a string Name field")),
            }
        }
        anyhow::bail!("could not find DagPb link '{}'", name);
    }

    #[tracing::instrument(skip(self))]
    async fn resolve_path_to_cid(&self, root: &Path, ctx: &mut LoaderContext) -> Result<Cid> {
        let mut current = root.clone();

        // maximum cursion of ipns lookups
        const MAX_LOOKUPS: usize = 16;

        for _ in 0..MAX_LOOKUPS {
            match current.typ() {
                PathType::Ipfs => match current.root() {
                    CidOrDomain::Cid(ref c) => {
                        return Ok(*c);
                    }
                    CidOrDomain::Domain(_) => bail!("invalid domain encountered"),
                },
                PathType::Ipns => match current.root() {
                    CidOrDomain::Cid(ref c) => {
                        let c = self.load_ipns_record(c).await?;
                        current = Path::from_cid(c);
                    }
                    CidOrDomain::Domain(ref domain) => {
                        let mut records = self.dns_resolver.resolve_dnslink(domain).await?;
                        if records.is_empty() {
                            bail!("no valid dnslink records found for {}", domain);
                        }
                        current = records.remove(0);
                    }
                },
            }
        }

        bail!("cannot resolve {}, too many recursive lookups", root);
    }

    #[tracing::instrument(skip(self))]
    async fn resolve_root(&self, root: &Path, ctx: &mut LoaderContext) -> Result<(Cid, LoadedCid)> {
        let cid = self.resolve_path_to_cid(root, ctx).await?;
        let loaded_cid = self.load_cid(&cid, ctx).await?;
        Ok((cid, loaded_cid))
    }

    #[tracing::instrument(skip(self))]
    async fn load_cid(&self, cid: &Cid, ctx: &mut LoaderContext) -> Result<LoadedCid> {
        self.loader.load_cid(cid, ctx).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn has_cid(&self, cid: &Cid) -> Result<bool> {
        self.loader.has_cid(cid).await
    }

    #[tracing::instrument(skip(self))]
    async fn load_ipns_record(&self, cid: &Cid) -> Result<Cid> {
        todo!()
    }
}

/// Read an `AsyncRead` into a `Vec` completely.
#[doc(hidden)]
pub async fn read_to_vec<T: AsyncRead + Unpin>(mut reader: T) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut out = Vec::new();
    reader.read_to_end(&mut out).await?;
    Ok(out)
}

/// Read a stream of (cid, block) pairs into an in memory store and return the store and the root cid.
#[doc(hidden)]
pub async fn stream_to_resolver(
    stream: impl Stream<Item = Result<Block>>,
) -> Result<(Cid, Resolver<Arc<fnv::FnvHashMap<Cid, Bytes>>>)> {
    tokio::pin!(stream);
    let blocks: Vec<_> = stream.try_collect().await?;
    for block in &blocks {
        block.validate()?;
    }
    let root_block = blocks.last().context("no root")?.clone();
    let store: fnv::FnvHashMap<Cid, Bytes> = blocks
        .into_iter()
        .map(|block| {
            let (cid, bytes, _) = block.into_parts();
            (cid, bytes)
        })
        .collect();
    let resolver = Resolver::new(Arc::new(store));
    Ok((*root_block.cid(), resolver))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        sync::Arc,
    };

    use super::*;
    use cid::multihash::{Code, MultihashDigest};
    use futures::{StreamExt, TryStreamExt};
    use libipld::{codec::Encode, Ipld, IpldCodec};
    use tokio::io::AsyncSeekExt;

    async fn load_fixture(p: &str) -> Bytes {
        Bytes::from(tokio::fs::read(format!("./fixtures/{p}")).await.unwrap())
    }

    async fn read_to_string<T: AsyncRead + Unpin>(reader: T) -> String {
        String::from_utf8(read_to_vec(reader).await.unwrap()).unwrap()
    }

    async fn seek_and_clip<T: ContentLoader + Unpin>(
        ctx: LoaderContext,
        node: &UnixfsNode,
        resolver: Resolver<T>,
        range: std::ops::Range<u64>,
    ) -> UnixfsContentReader<T> {
        let mut cr = node
            .clone()
            .into_content_reader(
                ctx,
                resolver.loader().clone(),
                OutMetrics::default(),
                Some(range.end as usize),
            )
            .unwrap()
            .unwrap();
        let n = cr
            .seek(tokio::io::SeekFrom::Start(range.start))
            .await
            .unwrap();
        assert_eq!(n, range.start);
        cr
    }

    #[test]
    fn test_paths() {
        let roundtrip_tests = [
            "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
            "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy/bar",
            "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy/bar/baz/foo",
            "/ipns/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
            "/ipns/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy/bar",
            "/ipns/ipfs.io",
        ];

        for test in roundtrip_tests {
            println!("{test}");
            let p: Path = test.parse().unwrap();
            assert_eq!(p.to_string(), test);
        }

        let valid_tests = [(
            "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
            "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
        )];
        for (test_in, test_out) in valid_tests {
            println!("{test_in}");
            let p: Path = test_in.parse().unwrap();
            assert_eq!(p.to_string(), test_out);
        }

        let invalid_tests = [
            "/bla/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
            "bla",
            "/bla/blub",
            "/ipfs/ipfs.io",
        ];
        for test in invalid_tests {
            println!("{test}");
            assert!(test.parse::<Path>().is_err());
        }
    }

    #[test]
    fn test_dir_paths() {
        let non_dir_test = "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy";
        let dir_test = "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy/";
        let non_dir_path: Path = non_dir_test.parse().unwrap();
        let dir_path: Path = dir_test.parse().unwrap();
        assert!(non_dir_path.tail().is_empty());
        assert_eq!(dir_path.tail().len(), 1);
        assert!(dir_path.tail()[0].is_empty());

        assert_eq!(non_dir_path.to_string(), non_dir_test);
        assert_eq!(dir_path.to_string(), dir_test);
        assert!(dir_path.has_trailing_slash());
        assert!(!non_dir_path.has_trailing_slash());
    }

    fn make_ipld() -> Ipld {
        let mut map = BTreeMap::new();
        map.insert("name".to_string(), Ipld::String("Foo".to_string()));
        map.insert("details".to_string(), Ipld::List(vec![Ipld::Integer(1)]));
        map.insert(
            "my-link".to_string(),
            Ipld::Link(
                "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
                    .parse()
                    .unwrap(),
            ),
        );

        Ipld::Map(map)
    }

    #[test]
    fn test_verify_hash() {
        for codec in [IpldCodec::DagCbor, IpldCodec::DagJson] {
            let ipld = make_ipld();

            let mut bytes = Vec::new();
            ipld.encode(codec, &mut bytes).unwrap();
            let digest = Code::Blake3_256.digest(&bytes);
            let c = Cid::new_v1(codec.into(), digest);

            assert_eq!(iroh_util::verify_hash(&c, &bytes), Some(true));
        }
    }

    #[test]
    fn test_parse_links() {
        for codec in [IpldCodec::DagCbor, IpldCodec::DagJson] {
            let ipld = make_ipld();

            let mut bytes = Vec::new();
            ipld.encode(codec, &mut bytes).unwrap();
            let digest = Code::Blake3_256.digest(&bytes);
            let c = Cid::new_v1(codec.into(), digest);

            let links = parse_links(&c, &bytes).unwrap();
            assert_eq!(links.len(), 1);
            assert_eq!(
                links[0].to_string(),
                "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
            );
        }
    }

    #[tokio::test]
    async fn test_resolve_ipld() {
        for codec in [IpldCodec::DagCbor, IpldCodec::DagJson] {
            let ipld = make_ipld();

            let mut bytes = Vec::new();
            ipld.encode(codec, &mut bytes).unwrap();
            let digest = Code::Blake3_256.digest(&bytes);
            let c = Cid::new_v1(codec.into(), digest);
            let bytes = Bytes::from(bytes);

            let loader: Arc<HashMap<_, _>> = Arc::new([(c, bytes)].into_iter().collect());
            let resolver = Resolver::new(loader.clone());

            {
                let path = format!("/ipfs/{c}/name");
                let new_ipld = resolver.resolve(path.parse().unwrap()).await.unwrap();
                let m = new_ipld.metadata().clone();

                let out_bytes = read_to_vec(
                    new_ipld
                        .pretty(resolver.clone(), OutMetrics::default(), None)
                        .unwrap(),
                )
                .await
                .unwrap();
                let out_ipld: Ipld = codec.decode(&out_bytes).unwrap();
                assert_eq!(out_ipld, Ipld::String("Foo".to_string()));

                assert_eq!(m.unixfs_type, None);
                assert_eq!(m.path.to_string(), path);
                match codec {
                    IpldCodec::DagCbor => {
                        assert_eq!(m.typ, OutType::DagCbor);
                    }
                    IpldCodec::DagJson => {
                        assert_eq!(m.typ, OutType::DagJson);
                    }
                    _ => unreachable!(),
                }
                assert_eq!(m.size, Some(out_bytes.len() as u64));
                assert_eq!(m.resolved_path, vec![c]);
            }
            {
                let path = format!("/ipfs/{c}/details/0");
                let new_ipld = resolver.resolve(path.parse().unwrap()).await.unwrap();
                let m = new_ipld.metadata().clone();

                let out_bytes = read_to_vec(
                    new_ipld
                        .pretty(resolver.clone(), OutMetrics::default(), None)
                        .unwrap(),
                )
                .await
                .unwrap();
                let out_ipld: Ipld = codec.decode(&out_bytes).unwrap();
                assert_eq!(out_ipld, Ipld::Integer(1));

                assert_eq!(m.unixfs_type, None);
                assert_eq!(m.path.to_string(), path);
                match codec {
                    IpldCodec::DagCbor => {
                        assert_eq!(m.typ, OutType::DagCbor);
                    }
                    IpldCodec::DagJson => {
                        assert_eq!(m.typ, OutType::DagJson);
                    }
                    _ => unreachable!(),
                }
                assert_eq!(m.size, Some(out_bytes.len() as u64));
                assert_eq!(m.resolved_path, vec![c]);
            }
        }
    }

    #[tokio::test]
    async fn test_unixfs_basics_cid_v0() {
        // Test content
        // ------------
        // QmaRGe7bVmVaLmxbrMiVNXqW4pRNNp3xq7hFtyRKA3mtJL foo/bar/bar.txt
        //   contains: "world"
        // QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN foo/hello.txt
        //   contains: "hello"
        // QmcHTZfwWWYG2Gbv9wR6bWZBvAgpFV5BcDoLrC2XMCkggn foo/bar
        // QmdkGfDx42RNdAZFALHn5hjHqUq7L9o6Ef4zLnFEu3Y4Go foo

        let bar_txt_cid_str = "QmaRGe7bVmVaLmxbrMiVNXqW4pRNNp3xq7hFtyRKA3mtJL";
        let bar_txt_block_bytes = load_fixture(bar_txt_cid_str).await;

        let bar_cid_str = "QmcHTZfwWWYG2Gbv9wR6bWZBvAgpFV5BcDoLrC2XMCkggn";
        let bar_block_bytes = load_fixture(bar_cid_str).await;

        let hello_txt_cid_str = "QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN";
        let hello_txt_block_bytes = load_fixture(hello_txt_cid_str).await;

        // read root
        let root_cid_str = "QmdkGfDx42RNdAZFALHn5hjHqUq7L9o6Ef4zLnFEu3Y4Go";
        let root_cid: Cid = root_cid_str.parse().unwrap();
        let root_block_bytes = load_fixture(root_cid_str).await;
        let root_block = UnixfsNode::decode(&root_cid, root_block_bytes.clone()).unwrap();

        let links: Vec<_> = root_block.links().collect::<Result<_>>().unwrap();
        assert_eq!(links.len(), 2);

        assert_eq!(links[0].cid, bar_cid_str.parse().unwrap());
        assert_eq!(links[0].name.unwrap(), "bar");

        assert_eq!(links[1].cid, hello_txt_cid_str.parse().unwrap());
        assert_eq!(links[1].name.unwrap(), "hello.txt");

        let loader: HashMap<Cid, Bytes> = [
            (root_cid, root_block_bytes.clone()),
            (hello_txt_cid_str.parse().unwrap(), hello_txt_block_bytes),
            (bar_cid_str.parse().unwrap(), bar_block_bytes),
            (bar_txt_cid_str.parse().unwrap(), bar_txt_block_bytes),
        ]
        .into_iter()
        .collect();
        let loader = Arc::new(loader);
        let resolver = Resolver::new(loader.clone());

        {
            let path = format!("/ipfs/{root_cid_str}");
            let ipld_foo = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let ls = ipld_foo
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .unwrap()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();
            assert_eq!(ls.len(), 2);
            assert_eq!(ls[0].name.as_ref().unwrap(), "bar");
            assert_eq!(ls[1].name.as_ref().unwrap(), "hello.txt");

            let m = ipld_foo.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::Dir));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, None);
            assert_eq!(m.resolved_path, vec![root_cid_str.parse().unwrap()]);
        }

        {
            let path = format!("/ipfs/{root_cid_str}/hello.txt");
            let ipld_hello_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            assert!(ipld_hello_txt
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .is_none());

            let m = ipld_hello_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(6));
            assert_eq!(
                m.resolved_path,
                vec![
                    root_cid_str.parse().unwrap(),
                    hello_txt_cid_str.parse().unwrap(),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_hello_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_hello_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None,
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "hello\n"
                );
            } else {
                panic!("invalid result: {ipld_hello_txt:?}");
            }
        }

        {
            let path = format!("/ipfs/{hello_txt_cid_str}");
            let ipld_hello_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            assert!(ipld_hello_txt
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .is_none());

            let m = ipld_hello_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(6));
            assert_eq!(m.resolved_path, vec![hello_txt_cid_str.parse().unwrap()]);

            if let OutContent::Unixfs(node) = ipld_hello_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_hello_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None,
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "hello\n"
                );
            } else {
                panic!("invalid result: {ipld_hello_txt:?}");
            }
        }

        {
            let path = format!("/ipfs/{root_cid_str}/bar");
            let ipld_bar = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let ls = ipld_bar
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .unwrap()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();
            assert_eq!(ls.len(), 1);
            assert_eq!(ls[0].name.as_ref().unwrap(), "bar.txt");

            let m = ipld_bar.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::Dir));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, None);
            assert_eq!(
                m.resolved_path,
                vec![root_cid_str.parse().unwrap(), bar_cid_str.parse().unwrap(),]
            );
        }

        {
            let path = format!("/ipfs/{root_cid_str}/bar/bar.txt");
            let ipld_bar_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let m = ipld_bar_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(6));
            assert_eq!(
                m.resolved_path,
                vec![
                    root_cid_str.parse().unwrap(),
                    bar_cid_str.parse().unwrap(),
                    bar_txt_cid_str.parse().unwrap(),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_bar_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None,
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "world\n"
                );
            } else {
                panic!("invalid result: {ipld_bar_txt:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_resolver_seeking() {
        // Test content
        // ------------
        // QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN foo/hello.txt
        //   contains: "hello"
        // QmdkGfDx42RNdAZFALHn5hjHqUq7L9o6Ef4zLnFEu3Y4Go foo

        let hello_txt_cid_str = "QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN";
        let hello_txt_block_bytes = load_fixture(hello_txt_cid_str).await;

        // read root
        let root_cid_str = "QmdkGfDx42RNdAZFALHn5hjHqUq7L9o6Ef4zLnFEu3Y4Go";
        let root_cid: Cid = root_cid_str.parse().unwrap();
        let root_block_bytes = load_fixture(root_cid_str).await;

        let loader: HashMap<Cid, Bytes> = [
            (root_cid, root_block_bytes.clone()),
            (hello_txt_cid_str.parse().unwrap(), hello_txt_block_bytes),
        ]
        .into_iter()
        .collect();
        let loader = Arc::new(loader);
        let resolver = Resolver::new(loader.clone());

        let path = format!("/ipfs/{root_cid_str}/hello.txt");
        let ipld_hello_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

        let ctx = ipld_hello_txt.context.clone();
        if let OutContent::Unixfs(node) = ipld_hello_txt.content {
            // clip response
            let cr = seek_and_clip(ctx.clone(), &node, resolver.clone(), 0..2).await;
            assert_eq!(read_to_string(cr).await, "he");

            let cr = seek_and_clip(ctx.clone(), &node, resolver.clone(), 0..5).await;
            assert_eq!(read_to_string(cr).await, "hello");

            // clip to the end
            let cr = seek_and_clip(ctx.clone(), &node, resolver.clone(), 0..6).await;
            assert_eq!(read_to_string(cr).await, "hello\n");

            // clip beyond the end
            let cr = seek_and_clip(ctx.clone(), &node, resolver.clone(), 0..100).await;
            assert_eq!(read_to_string(cr).await, "hello\n");

            // seek
            let cr = seek_and_clip(ctx.clone(), &node, resolver.clone(), 1..100).await;
            assert_eq!(read_to_string(cr).await, "ello\n");

            // seek and clip
            let cr = seek_and_clip(ctx.clone(), &node, resolver.clone(), 1..3).await;
            assert_eq!(read_to_string(cr).await, "el");
        } else {
            panic!("invalid result: {ipld_hello_txt:?}");
        }
    }

    #[tokio::test]
    async fn test_resolver_seeking_chunked() {
        // Test content
        // ------------
        // QmUr9cs4mhWxabKqm9PYPSQQ6AQGbHJBtyrNmxtKgxqUx9 README.md
        //
        // imported with `go-ipfs add --chunker size-100`

        let pieces_cid_str = [
            "QmccJ8pV5hG7DEbq66ih1ZtowxgvqVS6imt98Ku62J2WRw",
            "QmUajVwSkEp9JvdW914Qh1BCMRSUf2ztiQa6jqy1aWhwJv",
            "QmNyLad1dWGS6mv2zno4iEviBSYSUR2SrQ8JoZNDz1UHYy",
            "QmcXoBdCgmFMoNbASaQCNVswRuuuqbw4VvA7e5GtHbhRNp",
            "QmP9yKRwuji5i7RTgrevwJwXp7uqQu1prv88nxq9uj99rW",
        ];

        // read root
        let root_cid_str = "QmUr9cs4mhWxabKqm9PYPSQQ6AQGbHJBtyrNmxtKgxqUx9";
        let root_cid: Cid = root_cid_str.parse().unwrap();
        let root_block_bytes = load_fixture(root_cid_str).await;
        let root_block = UnixfsNode::decode(&root_cid, root_block_bytes.clone()).unwrap();

        let links: Vec<_> = root_block.links().collect::<Result<_>>().unwrap();
        assert_eq!(links.len(), 5);

        let mut loader: HashMap<Cid, Bytes> =
            [(root_cid, root_block_bytes.clone())].into_iter().collect();

        for c in &pieces_cid_str {
            let bytes = load_fixture(c).await;
            loader.insert(c.parse().unwrap(), bytes);
        }

        let loader = Arc::new(loader);
        let resolver = Resolver::new(loader.clone());

        {
            let path = format!("/ipfs/{root_cid_str}");
            let ipld_readme = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let m = ipld_readme.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(426));
            assert_eq!(m.resolved_path, vec![root_cid_str.parse().unwrap(),]);

            let size = m.size.unwrap();

            let ctx = ipld_readme.context.clone();
            if let OutContent::Unixfs(node) = ipld_readme.content {
                let cr = seek_and_clip(ctx.clone(), &node, resolver.clone(), 1..size - 1).await;
                let content = read_to_string(cr).await;
                assert_eq!(content.len(), (size - 2) as usize);
                assert!(content.starts_with(" iroh")); // without seeking '# iroh'
                assert!(content.ends_with("</sub>\n")); // without clipping '</sub>\n\n'

                let cr = seek_and_clip(ctx, &node, resolver.clone(), 101..size - 101).await;
                let content = read_to_string(cr).await;
                assert_eq!(content.len(), (size - 202) as usize);
                assert!(content.starts_with("2.0</a>"));
                assert!(content.ends_with("the Apac"));
            } else {
                panic!("invalid result: {ipld_readme:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_resolve_recursive_unixfs_basics_cid_v0() {
        // Test content
        // ------------
        // QmaRGe7bVmVaLmxbrMiVNXqW4pRNNp3xq7hFtyRKA3mtJL foo/bar/bar.txt
        //   contains: "world"
        // QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN foo/hello.txt
        //   contains: "hello"
        // QmcHTZfwWWYG2Gbv9wR6bWZBvAgpFV5BcDoLrC2XMCkggn foo/bar
        // QmdkGfDx42RNdAZFALHn5hjHqUq7L9o6Ef4zLnFEu3Y4Go foo

        let bar_txt_cid_str = "QmaRGe7bVmVaLmxbrMiVNXqW4pRNNp3xq7hFtyRKA3mtJL";
        let bar_txt_block_bytes = load_fixture(bar_txt_cid_str).await;

        let bar_cid_str = "QmcHTZfwWWYG2Gbv9wR6bWZBvAgpFV5BcDoLrC2XMCkggn";
        let bar_block_bytes = load_fixture(bar_cid_str).await;

        let hello_txt_cid_str = "QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN";
        let hello_txt_block_bytes = load_fixture(hello_txt_cid_str).await;

        // read root
        let root_cid_str = "QmdkGfDx42RNdAZFALHn5hjHqUq7L9o6Ef4zLnFEu3Y4Go";
        let root_cid: Cid = root_cid_str.parse().unwrap();
        let root_block_bytes = load_fixture(root_cid_str).await;
        let root_block = UnixfsNode::decode(&root_cid, root_block_bytes.clone()).unwrap();

        let links: Vec<_> = root_block.links().collect::<Result<_>>().unwrap();
        assert_eq!(links.len(), 2);

        assert_eq!(links[0].cid, bar_cid_str.parse().unwrap());
        assert_eq!(links[0].name.unwrap(), "bar");

        assert_eq!(links[1].cid, hello_txt_cid_str.parse().unwrap());
        assert_eq!(links[1].name.unwrap(), "hello.txt");

        let loader: HashMap<Cid, Bytes> = [
            (root_cid, root_block_bytes.clone()),
            (hello_txt_cid_str.parse().unwrap(), hello_txt_block_bytes),
            (bar_cid_str.parse().unwrap(), bar_block_bytes),
            (bar_txt_cid_str.parse().unwrap(), bar_txt_block_bytes),
        ]
        .into_iter()
        .collect();
        let loader = Arc::new(loader);
        let resolver = Resolver::new(loader.clone());

        let path = format!("/ipfs/{root_cid_str}");
        let results: Vec<_> = resolver
            .resolve_recursive(path.parse().unwrap())
            .try_collect()
            .await
            .unwrap();
        assert_eq!(results.len(), 4);

        for result in &results {
            assert_eq!(result.typ(), OutType::Unixfs);
        }

        assert_eq!(
            results[0].metadata().path.to_string(),
            format!("/ipfs/{root_cid_str}")
        );
        assert_eq!(
            results[1].metadata().path.to_string(),
            format!("/ipfs/{bar_cid_str}")
        );
        assert_eq!(
            results[2].metadata().path.to_string(),
            format!("/ipfs/{hello_txt_cid_str}")
        );
        assert_eq!(
            results[3].metadata().path.to_string(),
            format!("/ipfs/{bar_txt_cid_str}")
        );
    }

    #[tokio::test]
    async fn test_unixfs_basics_cid_v1() {
        // uses raw leaves

        // Test content
        // ------------
        // bafkreihcldjer7njjrrxknqh67cestxa7s7jf4nhnp62y6k4twcbahvtc4 foo/bar/bar.txt
        //   contains: "world"
        // bafkreicysg23kiwv34eg2d7qweipxwosdo2py4ldv42nbauguluen5v6am foo/hello.txt
        //   contains: "hello"
        // bafybeihmgpuwcdrfi47gfxisll7kmurvi6kd7rht5hlq2ed5omxobfip3a foo/bar
        // bafybeietod5kx72jgbngoontthoax6nva4edkjnieghwqfzenstg4gil5i foo

        let bar_txt_cid_str = "bafkreihcldjer7njjrrxknqh67cestxa7s7jf4nhnp62y6k4twcbahvtc4";
        let bar_txt_block_bytes = load_fixture(bar_txt_cid_str).await;

        let bar_cid_str = "bafybeihmgpuwcdrfi47gfxisll7kmurvi6kd7rht5hlq2ed5omxobfip3a";
        let bar_block_bytes = load_fixture(bar_cid_str).await;

        let hello_txt_cid_str = "bafkreicysg23kiwv34eg2d7qweipxwosdo2py4ldv42nbauguluen5v6am";
        let hello_txt_block_bytes = load_fixture(hello_txt_cid_str).await;

        // read root
        let root_cid_str = "bafybeietod5kx72jgbngoontthoax6nva4edkjnieghwqfzenstg4gil5i";
        let root_cid: Cid = root_cid_str.parse().unwrap();
        let root_block_bytes = load_fixture(root_cid_str).await;
        let root_block = UnixfsNode::decode(&root_cid, root_block_bytes.clone()).unwrap();

        let links: Vec<_> = root_block.links().collect::<Result<_>>().unwrap();
        assert_eq!(links.len(), 2);

        assert_eq!(links[0].cid, bar_cid_str.parse().unwrap());
        assert_eq!(links[0].name.unwrap(), "bar");

        assert_eq!(links[1].cid, hello_txt_cid_str.parse().unwrap());
        assert_eq!(links[1].name.unwrap(), "hello.txt");

        let loader: HashMap<Cid, Bytes> = [
            (root_cid, root_block_bytes.clone()),
            (hello_txt_cid_str.parse().unwrap(), hello_txt_block_bytes),
            (bar_cid_str.parse().unwrap(), bar_block_bytes),
            (bar_txt_cid_str.parse().unwrap(), bar_txt_block_bytes),
        ]
        .into_iter()
        .collect();
        let loader = Arc::new(loader);
        let resolver = Resolver::new(loader.clone());

        {
            let ipld_foo = resolver
                .resolve(root_cid_str.parse().unwrap())
                .await
                .unwrap();

            let ls = ipld_foo
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .unwrap()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();
            assert_eq!(ls.len(), 2);
            assert_eq!(ls[0].name.as_ref().unwrap(), "bar");
            assert_eq!(ls[1].name.as_ref().unwrap(), "hello.txt");
        }

        {
            let ipld_hello_txt = resolver
                .resolve(format!("{root_cid_str}/hello.txt").parse().unwrap())
                .await
                .unwrap();

            if let OutContent::Unixfs(node) = ipld_hello_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_hello_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None,
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "hello\n"
                );
            } else {
                panic!("invalid result: {ipld_hello_txt:?}");
            }
        }

        {
            let ipld_bar = resolver
                .resolve(format!("{root_cid_str}/bar").parse().unwrap())
                .await
                .unwrap();

            let ls = ipld_bar
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .unwrap()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();
            assert_eq!(ls.len(), 1);
            assert_eq!(ls[0].name.as_ref().unwrap(), "bar.txt");
        }

        {
            let ipld_bar_txt = resolver
                .resolve(format!("{root_cid_str}/bar/bar.txt").parse().unwrap())
                .await
                .unwrap();

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_bar_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "world\n"
                );
            } else {
                panic!("invalid result: {ipld_bar_txt:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_unixfs_split_file_regular() {
        // Test content
        // ------------
        // QmUr9cs4mhWxabKqm9PYPSQQ6AQGbHJBtyrNmxtKgxqUx9 README.md
        //
        // imported with `go-ipfs add --chunker size-100`

        let pieces_cid_str = [
            "QmccJ8pV5hG7DEbq66ih1ZtowxgvqVS6imt98Ku62J2WRw",
            "QmUajVwSkEp9JvdW914Qh1BCMRSUf2ztiQa6jqy1aWhwJv",
            "QmNyLad1dWGS6mv2zno4iEviBSYSUR2SrQ8JoZNDz1UHYy",
            "QmcXoBdCgmFMoNbASaQCNVswRuuuqbw4VvA7e5GtHbhRNp",
            "QmP9yKRwuji5i7RTgrevwJwXp7uqQu1prv88nxq9uj99rW",
        ];

        // read root
        let root_cid_str = "QmUr9cs4mhWxabKqm9PYPSQQ6AQGbHJBtyrNmxtKgxqUx9";
        let root_cid: Cid = root_cid_str.parse().unwrap();
        let root_block_bytes = load_fixture(root_cid_str).await;
        let root_block = UnixfsNode::decode(&root_cid, root_block_bytes.clone()).unwrap();

        let links: Vec<_> = root_block.links().collect::<Result<_>>().unwrap();
        assert_eq!(links.len(), 5);

        let mut loader: HashMap<Cid, Bytes> =
            [(root_cid, root_block_bytes.clone())].into_iter().collect();

        for c in &pieces_cid_str {
            let bytes = load_fixture(c).await;
            loader.insert(c.parse().unwrap(), bytes);
        }

        let loader = Arc::new(loader);
        let resolver = Resolver::new(loader.clone());

        {
            let path = format!("/ipfs/{root_cid_str}");
            let ipld_readme = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let m = ipld_readme.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(426));
            assert_eq!(m.resolved_path, vec![root_cid_str.parse().unwrap(),]);

            if let OutContent::Unixfs(node) = ipld_readme.content {
                let content = read_to_string(
                    node.into_content_reader(
                        ipld_readme.context,
                        resolver.loader().clone(),
                        OutMetrics::default(),
                        None,
                    )
                    .unwrap()
                    .unwrap(),
                )
                .await;
                print!("{content}");
                assert_eq!(content.len(), 426);
                assert!(content.starts_with("# iroh"));
                assert!(content.ends_with("</sub>\n\n"));
            } else {
                panic!("invalid result: {ipld_readme:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_unixfs_split_file_recursive() {
        // Test content
        // ------------
        // QmUr9cs4mhWxabKqm9PYPSQQ6AQGbHJBtyrNmxtKgxqUx9 README.md
        //
        // imported with `go-ipfs add --chunker size-100`

        let pieces_cid_str = [
            "QmccJ8pV5hG7DEbq66ih1ZtowxgvqVS6imt98Ku62J2WRw",
            "QmUajVwSkEp9JvdW914Qh1BCMRSUf2ztiQa6jqy1aWhwJv",
            "QmNyLad1dWGS6mv2zno4iEviBSYSUR2SrQ8JoZNDz1UHYy",
            "QmcXoBdCgmFMoNbASaQCNVswRuuuqbw4VvA7e5GtHbhRNp",
            "QmP9yKRwuji5i7RTgrevwJwXp7uqQu1prv88nxq9uj99rW",
        ];

        // read root
        let root_cid_str = "QmUr9cs4mhWxabKqm9PYPSQQ6AQGbHJBtyrNmxtKgxqUx9";
        let root_cid: Cid = root_cid_str.parse().unwrap();
        let root_block_bytes = load_fixture(root_cid_str).await;
        let root_block = UnixfsNode::decode(&root_cid, root_block_bytes.clone()).unwrap();

        let links: Vec<_> = root_block.links().collect::<Result<_>>().unwrap();
        assert_eq!(links.len(), 5);

        let mut loader: HashMap<Cid, Bytes> =
            [(root_cid, root_block_bytes.clone())].into_iter().collect();

        for c in &pieces_cid_str {
            let bytes = load_fixture(c).await;
            loader.insert(c.parse().unwrap(), bytes);
        }

        let loader = Arc::new(loader);
        let resolver = Resolver::new(loader.clone());

        {
            let path = format!("/ipfs/{root_cid_str}");
            let parts: Vec<_> = resolver
                .resolve_recursive(path.parse().unwrap())
                .try_collect()
                .await
                .unwrap();
            assert_eq!(parts.len(), 6);
            assert_eq!(parts[0].metadata().unixfs_type.unwrap(), UnixfsType::File);
            assert_eq!(parts[0].metadata().path, Path::from_cid(root_cid));
            assert_eq!(parts[1].metadata().path, pieces_cid_str[0].parse().unwrap());
            assert_eq!(parts[2].metadata().path, pieces_cid_str[1].parse().unwrap());
            assert_eq!(parts[3].metadata().path, pieces_cid_str[2].parse().unwrap());
            assert_eq!(parts[4].metadata().path, pieces_cid_str[3].parse().unwrap());
            assert_eq!(parts[5].metadata().path, pieces_cid_str[4].parse().unwrap());
        }
    }

    #[tokio::test]
    async fn test_unixfs_symlink() {
        // Test content
        // ------------
        // QmaRGe7bVmVaLmxbrMiVNXqW4pRNNp3xq7hFtyRKA3mtJL foo/bar/bar.txt
        //   contains: "world"
        // QmTh6zphkkZXhLimR5hfy1QnWrzf6EwP15r5aQqSzhUCYz foo/bar/my-symlink-local.txt
        //   contains: ./bar.txt
        // QmZSCBhytmu1Mr5gVrsXsB6D8S2XMQXSoofHdPxtPGrZBj foo/bar/my-symlink-outer.txt
        //   contains: ../../hello.txt (out of bounds)
        // QmRZQMR6cpczdJAF4xXtisda3DbvFrHxuwi5nF2NJKZvzC foo/bar/my-symlink.txt
        //   contains: ../hello.txt
        // QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN foo/hello.txt
        // QmT7qkMZnZNDACJ8CT4PnVkxXKJfcKNVggkygzRcvZE72B foo/bar
        // QmfTVUNatSpmZUERu62hwSEuLHEUNuY8FFuzFL5n187yGq foo

        let bar_txt_cid_str = "QmaRGe7bVmVaLmxbrMiVNXqW4pRNNp3xq7hFtyRKA3mtJL";
        let bar_txt_block_bytes = load_fixture(bar_txt_cid_str).await;

        let my_symlink_local_cid_str = "QmTh6zphkkZXhLimR5hfy1QnWrzf6EwP15r5aQqSzhUCYz";
        let my_symlink_local_block_bytes = load_fixture(my_symlink_local_cid_str).await;

        let my_symlink_cid_str = "QmRZQMR6cpczdJAF4xXtisda3DbvFrHxuwi5nF2NJKZvzC";
        let my_symlink_block_bytes = load_fixture(my_symlink_cid_str).await;

        let my_symlink_outer_cid_str = "QmZSCBhytmu1Mr5gVrsXsB6D8S2XMQXSoofHdPxtPGrZBj";
        let my_symlink_outer_block_bytes = load_fixture(my_symlink_outer_cid_str).await;

        let bar_cid_str = "QmT7qkMZnZNDACJ8CT4PnVkxXKJfcKNVggkygzRcvZE72B";
        let bar_block_bytes = load_fixture(bar_cid_str).await;

        let hello_txt_cid_str = "QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN";
        let hello_txt_block_bytes = load_fixture(hello_txt_cid_str).await;

        // read root
        let root_cid_str = "QmfTVUNatSpmZUERu62hwSEuLHEUNuY8FFuzFL5n187yGq";
        let root_cid: Cid = root_cid_str.parse().unwrap();
        let root_block_bytes = load_fixture(root_cid_str).await;
        let root_block = UnixfsNode::decode(&root_cid, root_block_bytes.clone()).unwrap();

        let links: Vec<_> = root_block.links().collect::<Result<_>>().unwrap();
        assert_eq!(links.len(), 2);

        assert_eq!(links[0].cid, bar_cid_str.parse().unwrap());
        assert_eq!(links[0].name.unwrap(), "bar");

        assert_eq!(links[1].cid, hello_txt_cid_str.parse().unwrap());
        assert_eq!(links[1].name.unwrap(), "hello.txt");

        let loader: HashMap<Cid, Bytes> = [
            (root_cid, root_block_bytes.clone()),
            (hello_txt_cid_str.parse().unwrap(), hello_txt_block_bytes),
            (bar_cid_str.parse().unwrap(), bar_block_bytes),
            (bar_txt_cid_str.parse().unwrap(), bar_txt_block_bytes),
            (my_symlink_cid_str.parse().unwrap(), my_symlink_block_bytes),
            (
                my_symlink_local_cid_str.parse().unwrap(),
                my_symlink_local_block_bytes,
            ),
            (
                my_symlink_outer_cid_str.parse().unwrap(),
                my_symlink_outer_block_bytes,
            ),
        ]
        .into_iter()
        .collect();
        let loader = Arc::new(loader);
        let resolver = Resolver::new(loader.clone());

        {
            let path = format!("/ipfs/{root_cid_str}/hello.txt");
            let ipld_hello_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            assert!(ipld_hello_txt
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .is_none());

            let m = ipld_hello_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(6));
            assert_eq!(
                m.resolved_path,
                vec![
                    root_cid_str.parse().unwrap(),
                    hello_txt_cid_str.parse().unwrap()
                ]
            );

            if let OutContent::Unixfs(node) = ipld_hello_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_hello_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "hello\n"
                );
            } else {
                panic!("invalid result: {ipld_hello_txt:?}");
            }
        }

        {
            let path = format!("/ipfs/{root_cid_str}/bar");
            let ipld_bar = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let ls = ipld_bar
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .unwrap()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();
            assert_eq!(ls.len(), 4);
            assert_eq!(ls[0].name.as_ref().unwrap(), "bar.txt");
            assert_eq!(ls[1].name.as_ref().unwrap(), "my-symlink-local.txt");
            assert_eq!(ls[2].name.as_ref().unwrap(), "my-symlink-outer.txt");
            assert_eq!(ls[3].name.as_ref().unwrap(), "my-symlink.txt");
        }

        // regular file
        {
            let path = format!("/ipfs/{root_cid_str}/bar/bar.txt");
            let ipld_bar_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let m = ipld_bar_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(6));
            assert_eq!(
                m.resolved_path,
                vec![
                    root_cid_str.parse().unwrap(),
                    bar_cid_str.parse().unwrap(),
                    bar_txt_cid_str.parse().unwrap()
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_bar_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "world\n"
                );
            } else {
                panic!("invalid result: {ipld_bar_txt:?}");
            }
        }

        // symlink local file
        {
            let path = format!("/ipfs/{root_cid_str}/bar/my-symlink-local.txt");
            let ipld_bar_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let m = ipld_bar_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::Symlink));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(
                m.resolved_path,
                vec![
                    root_cid_str.parse().unwrap(),
                    bar_cid_str.parse().unwrap(),
                    my_symlink_local_cid_str.parse().unwrap()
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_bar_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "./bar.txt"
                );
            } else {
                panic!("invalid result: {ipld_bar_txt:?}");
            }
        }

        // symlink outside
        {
            let path = format!("/ipfs/{root_cid_str}/bar/my-symlink-outer.txt");
            let ipld_bar_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let m = ipld_bar_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::Symlink));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(
                m.resolved_path,
                vec![
                    root_cid_str.parse().unwrap(),
                    bar_cid_str.parse().unwrap(),
                    my_symlink_outer_cid_str.parse().unwrap()
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_bar_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None,
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "../../hello.txt"
                );
            } else {
                panic!("invalid result: {ipld_bar_txt:?}");
            }
        }

        // symlink file
        {
            let path = format!("/ipfs/{root_cid_str}/bar/my-symlink.txt");
            let ipld_bar_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let m = ipld_bar_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::Symlink));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(
                m.resolved_path,
                vec![
                    root_cid_str.parse().unwrap(),
                    bar_cid_str.parse().unwrap(),
                    my_symlink_cid_str.parse().unwrap()
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_bar_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "../hello.txt"
                );
            } else {
                panic!("invalid result: {ipld_bar_txt:?}");
            }

            let path = format!("/ipfs/{my_symlink_cid_str}");
            let ipld_bar_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let m = ipld_bar_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::Symlink));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.resolved_path, vec![my_symlink_cid_str.parse().unwrap()]);

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_bar_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "../hello.txt"
                );
            } else {
                panic!("invalid result: {ipld_bar_txt:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_unixfs_hamt_dir() {
        // Test content
        // ------------
        // for n in $(seq 10000); do echo $n > foo/$n.txt; done
        // ipfs add --recursive foo
        //
        // QmUu8pzQ5yjhDrg4GiHYLeko2oT76vcmYX5bw6sjiEJ82k foo
        // QmWKbcq9HGfat7FsL85qrwNUxnmo3xAWzUo2nEj9BoAZeP foo/9999.txt

        let root_cid_str = "QmUu8pzQ5yjhDrg4GiHYLeko2oT76vcmYX5bw6sjiEJ82k";

        let reader = tokio::io::BufReader::new(
            tokio::fs::File::open("./fixtures/big-foo.car")
                .await
                .unwrap(),
        );
        let car_reader = iroh_car::CarReader::new(reader).await.unwrap();
        let files: HashMap<Cid, Bytes> = car_reader
            .stream()
            .map(|r| r.map(|(k, v)| (k, Bytes::from(v))))
            .try_collect()
            .await
            .unwrap();
        assert_eq!(files.len(), 10938);

        let loader = Arc::new(files);
        let resolver = Resolver::new(loader.clone());

        // foo/bar/bar.txt
        {
            let path = format!("/ipfs/{root_cid_str}/bar/bar.txt");
            let ipld_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            assert!(ipld_txt
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .is_none());

            let m = ipld_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert!(m.size.unwrap() > 0);

            if let OutContent::Unixfs(node) = ipld_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    "world\n",
                );
            } else {
                panic!("invalid result: {ipld_txt:?}");
            }
        }
        // read the directory listing
        {
            let path = format!("/ipfs/{root_cid_str}");
            let ipld_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let mut links = ipld_txt
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .expect("missing listing")
                .unwrap()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();
            // these are not sorted by name originally
            links.sort_by(|a, b| {
                let a = a.name.as_ref().unwrap();
                let b = b.name.as_ref().unwrap();

                match (
                    a.replace(".txt", "").parse::<usize>(),
                    b.replace(".txt", "").parse::<usize>(),
                ) {
                    (Ok(a), Ok(b)) => a.cmp(&b),
                    _ => a.cmp(b),
                }
            });

            for (i, link) in links.iter().take(10000).enumerate() {
                assert_eq!(link.name, Some(format!("{}.txt", i + 1)));
            }

            assert_eq!(links[10000].name, Some("bar".into()));
            assert_eq!(links[10001].name, Some("hello.txt".into()));

            assert_eq!(links.len(), 10_000 + 2);
        }

        for i in 1..=10000 {
            tokio::task::yield_now().await; // yield so sessions can be closed
            let path = format!("/ipfs/{root_cid_str}/{i}.txt");
            let ipld_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            assert!(ipld_txt
                .unixfs_read_dir(&resolver, OutMetrics::default())
                .unwrap()
                .is_none());

            let m = ipld_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert!(m.size.unwrap() > 0);

            if let OutContent::Unixfs(node) = ipld_txt.content {
                assert_eq!(
                    read_to_string(
                        node.into_content_reader(
                            ipld_txt.context,
                            resolver.loader().clone(),
                            OutMetrics::default(),
                            None
                        )
                        .unwrap()
                        .unwrap()
                    )
                    .await,
                    format!("{i}\n"),
                );
            } else {
                panic!("invalid result: {ipld_txt:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_resolve_recursive_with_path() {
        // Test content
        // ------------
        // QmaRGe7bVmVaLmxbrMiVNXqW4pRNNp3xq7hFtyRKA3mtJL foo/bar/bar.txt
        //   contains: "world"
        // QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN foo/hello.txt
        //   contains: "hello"
        // QmcHTZfwWWYG2Gbv9wR6bWZBvAgpFV5BcDoLrC2XMCkggn foo/bar
        // QmdkGfDx42RNdAZFALHn5hjHqUq7L9o6Ef4zLnFEu3Y4Go foo

        let bar_txt_cid_str = "QmaRGe7bVmVaLmxbrMiVNXqW4pRNNp3xq7hFtyRKA3mtJL";
        let bar_txt_block_bytes = load_fixture(bar_txt_cid_str).await;

        let bar_cid_str = "QmcHTZfwWWYG2Gbv9wR6bWZBvAgpFV5BcDoLrC2XMCkggn";
        let bar_block_bytes = load_fixture(bar_cid_str).await;

        let hello_txt_cid_str = "QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN";
        let hello_txt_block_bytes = load_fixture(hello_txt_cid_str).await;

        // read root
        let root_cid_str = "QmdkGfDx42RNdAZFALHn5hjHqUq7L9o6Ef4zLnFEu3Y4Go";
        let root_cid: Cid = root_cid_str.parse().unwrap();
        let root_block_bytes = load_fixture(root_cid_str).await;
        let root_block = UnixfsNode::decode(&root_cid, root_block_bytes.clone()).unwrap();

        let links: Vec<_> = root_block.links().collect::<Result<_>>().unwrap();
        assert_eq!(links.len(), 2);

        assert_eq!(links[0].cid, bar_cid_str.parse().unwrap());
        assert_eq!(links[0].name.unwrap(), "bar");

        assert_eq!(links[1].cid, hello_txt_cid_str.parse().unwrap());
        assert_eq!(links[1].name.unwrap(), "hello.txt");

        let loader: HashMap<Cid, Bytes> = [
            (root_cid, root_block_bytes.clone()),
            (hello_txt_cid_str.parse().unwrap(), hello_txt_block_bytes),
            (bar_cid_str.parse().unwrap(), bar_block_bytes),
            (bar_txt_cid_str.parse().unwrap(), bar_txt_block_bytes),
        ]
        .into_iter()
        .collect();
        let loader = Arc::new(loader);
        let resolver = Resolver::new(loader.clone());

        let path = format!("/ipfs/{root_cid_str}");
        let results: Vec<_> = resolver
            .resolve_recursive_with_paths(path.parse().unwrap())
            .try_collect()
            .await
            .unwrap();
        assert_eq!(results.len(), 4);

        assert_eq!(results[0].0.to_string(), format!("/ipfs/{root_cid_str}"));
        assert_eq!(
            results[1].0.to_string(),
            format!("/ipfs/{root_cid_str}/bar")
        );
        assert_eq!(
            results[2].0.to_string(),
            format!("/ipfs/{root_cid_str}/hello.txt")
        );
        assert_eq!(
            results[3].0.to_string(),
            format!("/ipfs/{root_cid_str}/bar/bar.txt")
        );
    }
}
