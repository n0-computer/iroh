use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    pin::Pin,
};

use anyhow::{ensure, Result};
use async_recursion::async_recursion;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use futures::{stream::LocalBoxStream, Stream, StreamExt};
use iroh_rpc_client::Client;
use prost::Message;
use tokio::io::AsyncRead;

use crate::{
    balanced_tree::{TreeBuilder, DEFAULT_DEGREE},
    chunker::{Chunker, DEFAULT_CHUNKS_SIZE, DEFAULT_CHUNK_SIZE_LIMIT},
    resolver::Block,
    unixfs::{dag_pb, unixfs_pb, DataType, Node, UnixfsNode},
};

// The maximum number of links we allow in a directory
// Any more links than this and we should switch to a hamt
// calculation comes from:
// (hash_length + max_file_name_len + tsize_len )/ block_size
// (64 bytes + 256 bytes + 8 bytes) / 2 MB ≈ 6400
// adding a generous buffer, we are using 6k as our link limit
const DIRECTORY_LINK_LIMIT: usize = 6000;

#[derive(Debug, PartialEq)]
enum DirectoryType {
    Basic,
    // TODO: writing hamt sharding not yet implemented
    Hamt,
}

/// Representation of a constructed Directory.
#[derive(Debug, PartialEq)]
pub struct Directory {
    name: String,
    entries: Vec<Entry>,
}

impl Directory {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Wrap an entry in an unnamed directory. Used when adding a unixfs file or top level directory to
    /// Iroh in order to preserve the file or directory's name.
    pub fn wrap(self) -> Self {
        Directory {
            name: "".into(),
            entries: vec![Entry::Directory(self)],
        }
    }

    pub async fn encode_root(self) -> Result<Block> {
        let mut current = None;
        let parts = self.encode();
        tokio::pin!(parts);

        while let Some(part) = parts.next().await {
            current = Some(part);
        }

        current.expect("must not be empty")
    }

    pub fn encode<'a>(self) -> LocalBoxStream<'a, Result<Block>> {
        async_stream::try_stream! {
            let mut links = Vec::new();
            for entry in self.entries {
                let (name, root) = match entry {
                    Entry::File(file) => {
                        let name = file.name().to_string();
                        let parts = file.encode().await?;
                        tokio::pin!(parts);
                        let mut root = None;
                        while let Some(part) = parts.next().await {
                            let block = part?;
                            root = Some(block.clone());
                            yield block;
                        }
                         (name, root)
                    }
                    Entry::Directory(dir) => {
                        let name = dir.name.clone();
                        let parts = dir.encode();
                        tokio::pin!(parts);
                        let mut root = None;
                        while let Some(part) = parts.next().await {
                            let block = part?;
                            root = Some(block.clone());
                            yield block;
                        }
                         (name, root)
                    }
                    Entry::Symlink(sym) => {
                        let name = sym.name().to_string();
                        let block = sym.encode()?;
                        let root = Some(block.clone());
                        yield block;
                        (name, root)
                    }
                };
                let root_block = root.expect("file must not be empty");
                links.push(dag_pb::PbLink {
                    hash: Some(root_block.cid().to_bytes()),
                    name: Some(name),
                    tsize: Some(root_block.data().len() as u64),
                });

            }

            // directory itself comes last
            let inner = unixfs_pb::Data {
                r#type: DataType::Directory as i32,
                ..Default::default()
            };
            let outer = encode_unixfs_pb(&inner, links)?;

            let node = UnixfsNode::Directory(Node { outer, inner });
            yield node.encode()?;
        }
        .boxed_local()
    }
}

enum Content {
    Reader(Pin<Box<dyn AsyncRead>>),
    Path(PathBuf),
}

impl Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Content::Reader(_) => write!(f, "Content::Reader(Pin<Box<dyn AsyncRead>>)"),
            Content::Path(p) => write!(f, "Content::Path({})", p.display()),
        }
    }
}

impl PartialEq for Content {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Content::Reader(_), Content::Reader(_)) => false,
            (Content::Path(self_path), Content::Path(other_path)) => self_path == other_path,
            _ => false,
        }
    }
}

/// Representation of a constructed File.
#[derive(PartialEq)]
pub struct File {
    name: String,
    content: Content,
    tree_builder: TreeBuilder,
    chunker: Chunker,
}

impl Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File")
            .field("name", &self.name)
            .field("content", &self.content)
            .field("tree_builder", &self.tree_builder)
            .field("chunker", &self.chunker)
            .finish()
    }
}

impl File {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn wrap(self) -> Directory {
        Directory {
            name: "".into(),
            entries: vec![Entry::File(self)],
        }
    }

    pub async fn encode_root(self) -> Result<Block> {
        let mut current = None;
        let parts = self.encode().await?;
        tokio::pin!(parts);

        while let Some(part) = parts.next().await {
            current = Some(part);
        }

        current.expect("must not be empty")
    }

    pub async fn encode(self) -> Result<impl Stream<Item = Result<Block>>> {
        let reader = match self.content {
            Content::Path(path) => {
                let f = tokio::fs::File::open(path).await?;
                let buf = tokio::io::BufReader::new(f);
                Box::pin(buf)
            }
            Content::Reader(reader) => reader,
        };
        let chunks = self.chunker.chunks(reader);
        Ok(self.tree_builder.stream_tree(chunks))
    }
}

/// Representation of a constructed Symlink.
#[derive(Debug, PartialEq, Eq)]
pub struct Symlink {
    name: String,
    target: PathBuf,
}

impl Symlink {
    pub fn new<P: Into<PathBuf>>(path: P, target: P) -> Self {
        Self {
            name: path
                .into()
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string(),
            target: target.into(),
        }
    }

    pub fn wrap(self) -> Directory {
        Directory {
            name: "".into(),
            entries: vec![Entry::Symlink(self)],
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn encode(self) -> Result<Block> {
        let target = self
            .target
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("target path {:?} is not valid unicode", self.target))?;
        let target = String::from(target);
        let inner = unixfs_pb::Data {
            r#type: DataType::Symlink as i32,
            data: Some(Bytes::from(target)),
            ..Default::default()
        };
        let outer = encode_unixfs_pb(&inner, Vec::new())?;
        let node = UnixfsNode::Symlink(Node { outer, inner });
        node.encode()
    }
}

/// Constructs a UnixFS file.
#[derive(Default)]
pub struct FileBuilder {
    name: Option<String>,
    path: Option<PathBuf>,
    reader: Option<Pin<Box<dyn AsyncRead>>>,
    chunk_size: Option<usize>,
    degree: Option<usize>,
}

impl Debug for FileBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reader = if self.reader.is_some() {
            "Some(Box<AsyncRead>)"
        } else {
            "None"
        };
        f.debug_struct("FileBuilder")
            .field("path", &self.path)
            .field("name", &self.name)
            .field("chunk_size", &self.chunk_size)
            .field("degree", &self.degree)
            .field("reader", &reader)
            .finish()
    }
}

/// FileBuilder separates uses a reader or bytes to chunk the data into raw unixfs nodes
impl FileBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn name<N: Into<String>>(&mut self, name: N) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    pub fn chunk_size(&mut self, chunk_size: usize) -> &mut Self {
        self.chunk_size = Some(chunk_size);
        self
    }

    pub fn degree(&mut self, degree: usize) -> &mut Self {
        self.degree = Some(degree);
        self
    }

    pub fn content_bytes<B: Into<Bytes>>(&mut self, content: B) -> &mut Self {
        let bytes = content.into();
        self.reader = Some(Box::pin(std::io::Cursor::new(bytes)));
        self
    }

    pub fn content_reader<T: tokio::io::AsyncRead + 'static>(&mut self, content: T) -> &mut Self {
        self.reader = Some(Box::pin(content));
        self
    }

    pub async fn build(self) -> Result<File> {
        let chunk_size = self.chunk_size.unwrap_or(DEFAULT_CHUNKS_SIZE);
        let degree = self.degree.unwrap_or(DEFAULT_DEGREE);
        let chunker = Chunker::fixed_with_size(chunk_size);
        let tree_builder = TreeBuilder::balanced_tree_with_degree(degree);
        if let Some(path) = self.path {
            let name = match self.name {
                Some(n) => n,
                None => path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string(),
            };
            return Ok(File {
                content: Content::Path(path),
                name,
                chunker,
                tree_builder,
            });
        }

        if let Some(reader) = self.reader {
            let name = self.name.ok_or_else(|| {
                anyhow::anyhow!("must add a name when building a file from a reader or bytes")
            })?;

            return Ok(File {
                content: Content::Reader(reader),
                name,
                chunker,
                tree_builder,
            });
        }
        anyhow::bail!("must have a path to the content or a reader for the content");
    }
}

/// Entry is the kind of entry in a directory can be either a file or a
/// folder (if recursive directories are allowed)
#[derive(Debug, PartialEq)]
enum Entry {
    File(File),
    Directory(Directory),
    Symlink(Symlink),
}

/// Construct a UnixFS directory.
#[derive(Debug)]
pub struct DirectoryBuilder {
    name: Option<String>,
    entries: Vec<Entry>,
    typ: DirectoryType,
}

impl Default for DirectoryBuilder {
    fn default() -> Self {
        Self {
            name: None,
            entries: Default::default(),
            typ: DirectoryType::Basic,
        }
    }
}

impl DirectoryBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn hamt(&mut self) -> &mut Self {
        self.typ = DirectoryType::Hamt;
        self
    }

    pub fn name<N: Into<String>>(&mut self, name: N) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    pub fn add_dir(&mut self, dir: Directory) -> Result<&mut Self> {
        Ok(self.entry(Entry::Directory(dir)))
    }

    pub fn add_file(&mut self, file: File) -> &mut Self {
        self.entry(Entry::File(file))
    }

    pub fn add_symlink(&mut self, symlink: Symlink) -> &mut Self {
        self.entry(Entry::Symlink(symlink))
    }

    fn entry(&mut self, entry: Entry) -> &mut Self {
        if self.typ == DirectoryType::Basic && self.entries.len() >= DIRECTORY_LINK_LIMIT {
            self.typ = DirectoryType::Hamt
        }
        self.entries.push(entry);
        self
    }

    pub fn build(self) -> Result<Directory> {
        let DirectoryBuilder {
            name, entries, typ, ..
        } = self;

        ensure!(typ == DirectoryType::Basic, "too many links to fit into one chunk, must be encoded as a HAMT. However, HAMT creation has not yet been implemented.");

        let name = name.unwrap_or_default();

        Ok(Directory { name, entries })
    }
}

/// Constructs a UnixFS Symlink
#[derive(Debug)]
pub struct SymlinkBuilder {
    path: PathBuf,
    target: Option<PathBuf>,
}

impl SymlinkBuilder {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            target: None,
        }
    }

    pub fn target<P: Into<PathBuf>>(&mut self, target: P) -> &mut Self {
        self.target = Some(target.into());
        self
    }

    pub async fn build(self) -> Result<Symlink> {
        let name = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let target = match self.target {
            Some(target) => target,
            None => tokio::fs::read_link(&self.path).await?,
        };
        Ok(Symlink { name, target })
    }
}

pub(crate) fn encode_unixfs_pb(
    inner: &unixfs_pb::Data,
    links: Vec<dag_pb::PbLink>,
) -> Result<dag_pb::PbNode> {
    let data = inner.encode_to_vec();
    ensure!(
        data.len() <= DEFAULT_CHUNK_SIZE_LIMIT,
        "node is too large: {} bytes",
        data.len()
    );

    Ok(dag_pb::PbNode {
        links,
        data: Some(data.into()),
    })
}

#[async_trait]
pub trait Store {
    async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()>;
}

#[async_trait]
impl Store for &Client {
    async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        self.try_store()?.put(cid, blob, links).await
    }
}

#[derive(Debug)]
pub struct StoreAndProvideClient {
    pub client: Client,
}

#[async_trait]
impl Store for StoreAndProvideClient {
    async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        self.client.try_store()?.put(cid, blob, links).await?;
        self.client.try_p2p()?.start_providing(&cid).await
    }
}

#[async_trait]
impl Store for &tokio::sync::Mutex<std::collections::HashMap<Cid, Bytes>> {
    async fn put(&self, cid: Cid, blob: Bytes, _links: Vec<Cid>) -> Result<()> {
        self.lock().await.insert(cid, blob);
        Ok(())
    }
}

/// Adds a single file.
/// - storing the content using `rpc.store`
/// - returns a stream of AddEvent
/// - optionally wraps into a UnixFs directory to preserve the filename
pub async fn add_file<S: Store>(
    store: Option<S>,
    path: &Path,
    wrap: bool,
) -> Result<impl Stream<Item = Result<AddEvent>>> {
    ensure!(path.is_file(), "provided path was not a file");

    let file = FileBuilder::new().path(path).build().await?;

    let blocks = {
        if wrap {
            // wrap file in dir to preserve file name
            file.wrap().encode()
        } else {
            Box::pin(file.encode().await?)
        }
    };
    add_blocks_to_store(store, blocks).await
}

/// Adds a directory.
/// - storing the content using `rpc.store`
/// - returns a stream of AddEvent
/// - optionally wraps into a UnixFs directory to preserve the directory name
pub async fn add_dir<S: Store>(
    store: Option<S>,
    path: &Path,
    wrap: bool,
) -> Result<impl Stream<Item = Result<AddEvent>>> {
    ensure!(path.is_dir(), "provided path was not a directory");

    let dir = make_dir_from_path(path).await?;

    // encode and store
    let blocks = {
        if wrap {
            // wrap dir in dir to preserve file name
            dir.wrap().encode()
        } else {
            dir.encode()
        }
    };

    let stream = add_blocks_to_store(store, blocks).await?;

    Ok(stream)
}

/// Adds a symlink
pub async fn add_symlink<S: Store>(
    store: Option<S>,
    path: &Path,
    wrap: bool,
) -> Result<impl Stream<Item = Result<AddEvent>>> {
    ensure!(path.is_symlink(), "provided path was not a symlink");
    let symlink = SymlinkBuilder::new(path).build().await?;
    if wrap {
        let dir = symlink.wrap();
        let blocks = dir.encode();
        return add_blocks_to_store(store, blocks).await;
    }
    let blocks = Box::pin(async_stream::try_stream! {
        yield symlink.encode()?
    });
    let stream = add_blocks_to_store(store, blocks).await?;

    // let (cid, bytes, links) = symlink.encode()?.into_parts();
    // if let Some(ref store) = store {
    //     store.put(cid, bytes, links).await?;
    // }
    // let stream = async_stream::try_stream! {
    //     yield AddEvent::Done(cid);
    // };
    Ok(stream)
}

/// An event on the add stream
pub enum AddEvent {
    /// Delta of progress in bytes
    ProgressDelta(u64),
    /// The root Cid of the added file, produced once in the end
    Done(Cid),
}

pub async fn add_blocks_to_store<S: Store>(
    store: Option<S>,
    mut blocks: Pin<Box<dyn Stream<Item = Result<Block>>>>,
) -> Result<impl Stream<Item = Result<AddEvent>>> {
    let stream = async_stream::try_stream! {

        let mut root = None;
        while let Some(block) = blocks.next().await {
            let block = block?;
            let raw_data_size = block.raw_data_size();
            let (cid, bytes, links) = block.into_parts();
            if let Some(ref store) = store {
                store.put(cid, bytes, links).await?;
            }
            if let Some(raw_data_size) = raw_data_size {
                yield AddEvent::ProgressDelta(raw_data_size);
            }
            root = Some(cid);
        }

        yield AddEvent::Done(root.expect("missing root"))
    };
    Ok(stream)
}

#[async_recursion(?Send)]
async fn make_dir_from_path<P: Into<PathBuf>>(path: P) -> Result<Directory> {
    let path = path.into();
    let mut dir = DirectoryBuilder::new();
    dir.name(
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default(),
    );
    let mut directory_reader = tokio::fs::read_dir(path.clone()).await?;
    while let Some(entry) = directory_reader.next_entry().await? {
        let path = entry.path();
        if path.is_symlink() {
            let s = SymlinkBuilder::new(path).build().await?;
            dir.add_symlink(s);
        } else if path.is_file() {
            let f = FileBuilder::new().path(path).build().await?;
            dir.add_file(f);
        } else if path.is_dir() {
            let d = make_dir_from_path(path).await?;
            dir.add_dir(d)?;
        } else {
            anyhow::bail!("directory entry is neither file nor directory")
        }
    }
    dir.build()
}

#[cfg(test)]
mod tests {
    use crate::resolver::{ContentLoader, Out, OutMetrics, Resolver};

    use super::*;
    use crate::resolver::ResponseClip;
    use anyhow::{Context, Result};
    use futures::TryStreamExt;
    use proptest::prelude::*;
    use rand::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use std::{collections::BTreeMap, io::prelude::*, sync::Arc};
    use tempfile;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_builder_basics() -> Result<()> {
        // Create a directory
        let mut dir = DirectoryBuilder::new();
        dir.name("foo");

        // Add a file
        let mut bar = FileBuilder::new();
        bar.name("bar.txt").content_bytes(b"bar".to_vec());
        let bar = bar.build().await?;
        let bar_encoded: Vec<_> = {
            let mut bar = FileBuilder::new();
            bar.name("bar.txt").content_bytes(b"bar".to_vec());
            let bar = bar.build().await?;
            bar.encode().await?.try_collect().await?
        };
        assert_eq!(bar_encoded.len(), 1);

        // Add a symlink
        let mut baz = SymlinkBuilder::new("baz.txt");
        baz.target("bat.txt");
        let baz = baz.build().await?;
        let baz_encoded: Block = {
            let mut baz = SymlinkBuilder::new("baz.txt");
            baz.target("bat.txt");
            let baz = baz.build().await?;
            baz.encode()?
        };

        dir.add_file(bar).add_symlink(baz);

        let dir = dir.build()?;

        let dir_block = dir.encode_root().await?;
        let decoded_dir = UnixfsNode::decode(dir_block.cid(), dir_block.data().clone())?;

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, *bar_encoded[0].cid());
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, *baz_encoded.cid());

        // TODO: check content
        Ok(())
    }

    #[tokio::test]
    async fn test_recursive_dir_builder() -> Result<()> {
        let dir = DirectoryBuilder::new();
        let dir = dir.build()?;

        let mut recursive_dir_builder = DirectoryBuilder::new();
        recursive_dir_builder
            .add_dir(dir)
            .expect("recursive directories allowed");
        Ok(())
    }

    #[tokio::test]
    async fn test_builder_stream_small() -> Result<()> {
        // Create a directory
        let mut dir = DirectoryBuilder::new();
        dir.name("foo");

        // Add a file
        let mut bar = FileBuilder::new();
        let bar_reader = std::io::Cursor::new(b"bar");
        bar.name("bar.txt").content_reader(bar_reader);
        let bar = bar.build().await?;
        let bar_encoded: Vec<_> = {
            let mut bar = FileBuilder::new();
            let bar_reader = std::io::Cursor::new(b"bar");
            bar.name("bar.txt").content_reader(bar_reader);
            let bar = bar.build().await?;
            bar.encode().await?.try_collect().await?
        };
        assert_eq!(bar_encoded.len(), 1);

        // Add a symlink
        let mut baz = SymlinkBuilder::new("baz.txt");
        baz.target("bat.txt");
        let baz = baz.build().await?;
        let baz_encoded: Block = {
            let mut baz = SymlinkBuilder::new("baz.txt");
            baz.target("bat.txt");
            let baz = baz.build().await?;
            baz.encode()?
        };

        dir.add_file(bar).add_symlink(baz);

        let dir = dir.build()?;

        let dir_block = dir.encode_root().await?;
        let decoded_dir = UnixfsNode::decode(dir_block.cid(), dir_block.data().clone())?;

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, *bar_encoded[0].cid());
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, *baz_encoded.cid());

        // TODO: check content
        Ok(())
    }

    // read an AsyncRead into a vec completely
    async fn read_to_vec<T: AsyncRead + Unpin>(mut reader: T) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await?;
        Ok(out)
    }

    /// Read a stream of (cid, block) pairs into an in memory store and return the store and the root cid
    async fn stream_to_resolver(
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TestDirEntry {
        File(Bytes),
        Directory(TestDir),
    }
    type TestDir = BTreeMap<String, TestDirEntry>;

    /// builds an unixfs directory out of a TestDir
    #[async_recursion(?Send)]
    async fn build_directory(name: &str, dir: &TestDir) -> Result<Directory> {
        let mut builder = DirectoryBuilder::new();
        builder.name(name);
        for (name, entry) in dir {
            match entry {
                TestDirEntry::File(content) => {
                    let mut file = FileBuilder::new();
                    file.name(name).content_bytes(content.to_vec());
                    builder.add_file(file.build().await?);
                }
                TestDirEntry::Directory(dir) => {
                    let dir = build_directory(name, dir).await?;
                    builder.add_dir(dir)?;
                }
            }
        }
        builder.build()
    }

    /// builds a TestDir out of a stream of blocks and a resolver
    async fn build_testdir(
        stream: impl Stream<Item = Result<(crate::resolver::Path, Out)>>,
        resolver: Resolver<impl ContentLoader + Unpin>,
    ) -> Result<TestDir> {
        tokio::pin!(stream);

        /// recursively create directories for a path
        fn mkdir(dir: &mut TestDir, path: &[String]) -> Result<()> {
            if let Some((first, rest)) = path.split_first() {
                if let TestDirEntry::Directory(child) = dir
                    .entry(first.clone())
                    .or_insert_with(|| TestDirEntry::Directory(Default::default()))
                {
                    mkdir(child, rest)?;
                } else {
                    anyhow::bail!("not a directory");
                }
            }
            Ok(())
        }

        /// create a file in a directory hierarchy
        fn mkfile(dir: &mut TestDir, path: &[String], data: Bytes) -> Result<()> {
            if let Some((first, rest)) = path.split_first() {
                if rest.is_empty() {
                    dir.insert(first.clone(), TestDirEntry::File(data));
                } else if let TestDirEntry::Directory(child) = dir
                    .entry(first.clone())
                    .or_insert_with(|| TestDirEntry::Directory(Default::default()))
                {
                    mkfile(child, rest, data)?;
                } else {
                    anyhow::bail!("not a directory");
                }
            }
            Ok(())
        }

        let reference = stream
            .try_fold(TestDir::default(), move |mut agg, (path, item)| {
                let resolver = resolver.clone();
                async move {
                    if item.is_dir() {
                        mkdir(&mut agg, path.tail())?;
                    } else {
                        let reader = item.pretty(
                            resolver.clone(),
                            OutMetrics::default(),
                            ResponseClip::NoClip,
                        )?;
                        let data = read_to_vec(reader).await?;
                        mkfile(&mut agg, path.tail(), data.into())?;
                    }
                    Ok(agg)
                }
            })
            .await?;
        Ok(reference)
    }

    /// a roundtrip test that converts a dir to an unixfs DAG and back
    async fn dir_roundtrip_test(dir: TestDir) -> Result<bool> {
        let directory = build_directory("", &dir).await?;
        let stream = directory.encode();
        let (root, resolver) = stream_to_resolver(stream).await?;
        let stream = resolver.resolve_recursive_with_paths(crate::resolver::Path::from_cid(root));
        let reference = build_testdir(stream, resolver).await?;
        Ok(dir == reference)
    }

    /// sync version of dir_roundtrip_test for use in proptest
    fn dir_roundtrip_test_sync(dir: TestDir) -> bool {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(dir_roundtrip_test(dir))
            .unwrap()
    }

    /// a roundtrip test that converts a file to an unixfs DAG and back
    async fn file_roundtrip_test(data: Bytes, chunk_size: usize, degree: usize) -> Result<bool> {
        let mut builder = FileBuilder::new();
        builder
            .name("file.bin")
            .chunk_size(chunk_size)
            .degree(degree)
            .content_bytes(data.clone());
        let file = builder.build().await?;
        let stream = file.encode().await?;
        let (root, resolver) = stream_to_resolver(stream).await?;
        let out = resolver
            .resolve(crate::resolver::Path::from_cid(root))
            .await?;
        let t =
            read_to_vec(out.pretty(resolver, OutMetrics::default(), ResponseClip::NoClip)?).await?;
        println!("{}", data.len());
        Ok(t == data)
    }

    /// a roundtrip test that converts a symlink to a unixfs DAG and back
    #[tokio::test]
    async fn symlink_roundtrip_test() -> Result<()> {
        let mut builder = SymlinkBuilder::new("foo");
        let target = "../../bar.txt";
        builder.target(target);
        let sym = builder.build().await?;
        let block = sym.encode()?;
        let stream = async_stream::try_stream! {
            yield block;
        };
        let (root, resolver) = stream_to_resolver(stream).await?;
        let out = resolver
            .resolve(crate::resolver::Path::from_cid(root))
            .await?;
        let mut reader = out.pretty(resolver, OutMetrics::default(), ResponseClip::NoClip)?;
        let mut t = String::new();
        reader.read_to_string(&mut t).await?;
        println!("{}", t);
        assert_eq!(target, t);
        Ok(())
    }

    #[tokio::test]
    async fn symlink_from_disk_test() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let expect_name = "path_to_symlink";
        let expect_target = temp_dir.path().join("path_to_target");
        let expect_path = temp_dir.path().join(expect_name);

        tokio::fs::symlink(expect_target.clone(), expect_path.clone()).await?;

        let got_symlink = SymlinkBuilder::new(expect_path).build().await?;
        assert_eq!(expect_name, got_symlink.name());
        assert_eq!(expect_target, got_symlink.target);
        Ok(())
    }

    /// sync version of file_roundtrip_test for use in proptest
    fn file_roundtrip_test_sync(data: Bytes, chunk_size: usize, degree: usize) -> bool {
        let f = file_roundtrip_test(data, chunk_size, degree);
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
            .unwrap()
    }

    fn arb_test_dir() -> impl Strategy<Value = TestDir> {
        // create an arbitrary nested directory structure
        fn arb_dir_entry() -> impl Strategy<Value = TestDirEntry> {
            let leaf = any::<Vec<u8>>().prop_map(|x| TestDirEntry::File(Bytes::from(x)));
            leaf.prop_recursive(3, 64, 10, |inner| {
                prop::collection::btree_map(".*", inner, 0..10).prop_map(TestDirEntry::Directory)
            })
        }
        prop::collection::btree_map(".*", arb_dir_entry(), 0..10)
    }

    fn arb_degree() -> impl Strategy<Value = usize> {
        // use either the smallest possible degree for complex tree structures, or the default value for realism
        prop_oneof![Just(2), Just(DEFAULT_DEGREE)]
    }

    fn arb_chunk_size() -> impl Strategy<Value = usize> {
        // use either the smallest possible chunk size for complex tree structures, or the default value for realism
        prop_oneof![Just(1), Just(DEFAULT_CHUNKS_SIZE)]
    }

    proptest! {
        #[test]
        fn test_file_roundtrip(data in proptest::collection::vec(any::<u8>(), 0usize..1024), chunk_size in arb_chunk_size(), degree in arb_degree()) {
            assert!(file_roundtrip_test_sync(data.into(), chunk_size, degree));
        }

        #[test]
        fn test_dir_roundtrip(data in arb_test_dir()) {
            assert!(dir_roundtrip_test_sync(data));
        }
    }

    #[tokio::test]
    async fn test_builder_roundtrip_complex_tree_1() -> Result<()> {
        // fill with random data so we get distinct cids for all blocks
        let mut rng = ChaCha8Rng::from_seed([0; 32]);
        let mut data = vec![0u8; 1024 * 128];
        rng.fill(data.as_mut_slice());
        assert!(file_roundtrip_test(data.into(), 1024, 4).await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_builder_roundtrip_128m() -> Result<()> {
        // fill with random data so we get distinct cids for all blocks
        let mut rng = ChaCha8Rng::from_seed([0; 32]);
        let mut data = vec![0u8; 128 * 1024 * 1024];
        rng.fill(data.as_mut_slice());
        assert!(file_roundtrip_test(data.into(), DEFAULT_CHUNKS_SIZE, DEFAULT_DEGREE).await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_builder_stream_large() -> Result<()> {
        // Create a directory
        let mut dir = DirectoryBuilder::new();
        dir.name("foo");

        // Add a file
        let mut bar = FileBuilder::new();
        let bar_reader = std::io::Cursor::new(vec![1u8; 1024 * 1024]);
        bar.name("bar.txt").content_reader(bar_reader);
        let bar = bar.build().await?;
        let bar_encoded: Vec<_> = {
            let mut bar = FileBuilder::new();
            let bar_reader = std::io::Cursor::new(vec![1u8; 1024 * 1024]);
            bar.name("bar.txt").content_reader(bar_reader);
            let bar = bar.build().await?;
            bar.encode().await?.try_collect().await?
        };
        assert_eq!(bar_encoded.len(), 5);

        // Add a file
        let mut baz = FileBuilder::new();
        let mut baz_content = Vec::with_capacity(1024 * 1024 * 2);
        for i in 0..2 {
            for _ in 0..(1024 * 1024) {
                baz_content.push(i);
            }
        }

        let baz_reader = std::io::Cursor::new(baz_content.clone());
        baz.name("baz.txt").content_reader(baz_reader);
        let baz = baz.build().await?;
        let baz_encoded: Vec<_> = {
            let mut baz = FileBuilder::new();
            let baz_reader = std::io::Cursor::new(baz_content);
            baz.name("baz.txt").content_reader(baz_reader);
            let baz = baz.build().await?;
            baz.encode().await?.try_collect().await?
        };
        assert_eq!(baz_encoded.len(), 9);

        dir.add_file(bar).add_file(baz);

        let dir = dir.build()?;

        let dir_block = dir.encode_root().await?;
        let decoded_dir = UnixfsNode::decode(dir_block.cid(), dir_block.data().clone())?;

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, *bar_encoded[4].cid());
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, *baz_encoded[8].cid());

        for (i, encoded) in baz_encoded.iter().enumerate() {
            let node = UnixfsNode::decode(encoded.cid(), encoded.data().clone())?;
            if i == 8 {
                assert_eq!(node.typ(), Some(DataType::File));
                assert_eq!(node.links().count(), 8);
            } else {
                assert_eq!(node.typ(), None); // raw leaves
                assert_eq!(node.size(), Some(1024 * 256));
                assert_eq!(node.links().count(), 0);
            }
        }

        // TODO: check content
        // TODO: add nested directory

        Ok(())
    }

    #[tokio::test]
    async fn test_hamt_detection() -> Result<()> {
        // allow hamt override
        let mut builder = DirectoryBuilder::new();
        builder.hamt();
        assert_eq!(DirectoryType::Hamt, builder.typ);

        let mut builder = DirectoryBuilder::new();

        for _i in 0..DIRECTORY_LINK_LIMIT {
            let mut file_builder = FileBuilder::new();
            file_builder.name("foo.txt");
            file_builder.content_bytes(Bytes::from("hello world"));
            let file = file_builder.build().await?;
            builder.add_file(file);
        }

        // under DIRECTORY_LINK_LIMIT should still be a basic directory
        assert_eq!(DirectoryType::Basic, builder.typ);

        let mut file_builder = FileBuilder::new();
        file_builder.name("foo.txt");
        file_builder.content_bytes(Bytes::from("hello world"));
        let file = file_builder.build().await?;
        builder.add_file(file);

        // at directory link limit should be processed as a hamt
        assert_eq!(DirectoryType::Hamt, builder.typ);
        if (builder.build()).is_ok() {
            panic!("expected builder to error when attempting to build a hamt directory")
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_make_dir_from_path() -> Result<()> {
        let temp_dir = std::env::temp_dir();
        let dir = temp_dir.join("test_dir");
        std::fs::DirBuilder::new()
            .recursive(true)
            .create(dir.clone())
            .unwrap();

        // create directory and nested file
        let nested_dir_path = dir.join("nested_dir");
        let nested_file_path = nested_dir_path.join("bar.txt");

        std::fs::DirBuilder::new()
            .recursive(true)
            .create(nested_dir_path.clone())
            .unwrap();

        let mut file = std::fs::File::create(nested_file_path.clone()).unwrap();
        file.write_all(b"hello world again").unwrap();

        // create another file in the "test_dir" directory
        let file_path = dir.join("foo.txt");
        let mut file = std::fs::File::create(file_path.clone()).unwrap();
        file.write_all(b"hello world").unwrap();

        // create directory manually
        let nested_file = FileBuilder::new().path(nested_file_path).build().await?;
        let nested_dir = Directory {
            name: String::from(
                nested_dir_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap(),
            ),
            entries: vec![Entry::File(nested_file)],
        };

        let file = FileBuilder::new().path(file_path).build().await?;

        let expected = Directory {
            name: String::from(dir.clone().file_name().and_then(|s| s.to_str()).unwrap()),
            entries: vec![Entry::File(file), Entry::Directory(nested_dir)],
        };

        let mut got = make_dir_from_path(dir).await?;

        // Before comparison sort entries to make test deterministic.
        // The readdir_r function is used in the underlying platform which
        // gives no guarantee to return in a specific order.
        // https://stackoverflow.com/questions/40021882/how-to-sort-readdir-iterator
        got.entries.sort_by_key(|entry| match entry {
            Entry::Directory(dir) => dir.name.clone(),
            Entry::File(file) => file.name.clone(),
            Entry::Symlink(sym) => sym.name().to_string(),
        });

        assert_eq!(expected, got);
        Ok(())
    }
}
