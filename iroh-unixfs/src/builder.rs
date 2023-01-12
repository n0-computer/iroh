use std::{
    collections::BTreeMap,
    fmt::Debug,
    path::{Path, PathBuf},
    pin::Pin,
};

use anyhow::{ensure, Context, Result};
use async_recursion::async_recursion;
use bytes::Bytes;
use futures::{
    stream::{self, BoxStream},
    Stream, StreamExt, TryFutureExt,
};
use prost::Message;
use tokio::io::AsyncRead;

use crate::{
    balanced_tree::{TreeBuilder, DEFAULT_DEGREE},
    chunker::{self, Chunker, ChunkerConfig, DEFAULT_CHUNK_SIZE_LIMIT},
    hamt::{bitfield::Bitfield, bits, hash_key},
    types::Block,
    unixfs::{dag_pb, unixfs_pb, DataType, HamtHashFunction, Node, UnixfsNode},
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
pub enum Directory {
    Basic(BasicDirectory),
    Hamt(HamtDirectory),
}

/// A basic / flat directory
#[derive(Debug, PartialEq)]
pub struct BasicDirectory {
    name: String,
    entries: Vec<Entry>,
}

/// A hamt sharded directory
#[derive(Debug, PartialEq)]
pub struct HamtDirectory {
    name: String,
    hamt: Box<HamtNode>,
}

impl Directory {
    fn single(name: String, entry: Entry) -> Self {
        Directory::basic(name, vec![entry])
    }

    pub fn basic(name: String, entries: Vec<Entry>) -> Self {
        Directory::Basic(BasicDirectory { name, entries })
    }

    pub fn name(&self) -> &str {
        match &self {
            Directory::Basic(BasicDirectory { name, .. }) => name,
            Directory::Hamt(HamtDirectory { name, .. }) => name,
        }
    }

    pub fn set_name(&mut self, value: String) {
        match self {
            Directory::Basic(BasicDirectory { name, .. }) => {
                *name = value;
            }
            Directory::Hamt(HamtDirectory { name, .. }) => {
                *name = value;
            }
        }
    }

    /// Wrap an entry in an unnamed directory. Used when adding a unixfs file or top level directory to
    /// Iroh in order to preserve the file or directory's name.
    pub fn wrap(self) -> Self {
        Directory::single("".into(), Entry::Directory(self))
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

    pub fn encode<'a>(self) -> BoxStream<'a, Result<Block>> {
        match self {
            Directory::Basic(basic) => basic.encode(),
            Directory::Hamt(hamt) => hamt.encode(),
        }
    }
}

impl BasicDirectory {
    pub fn encode<'a>(self) -> BoxStream<'a, Result<Block>> {
        async_stream::try_stream! {
            let mut links = Vec::new();
            for entry in self.entries {
                let name = entry.name().to_string();
                let parts = entry.encode().await?;
                tokio::pin!(parts);
                let mut root = None;
                while let Some(part) = parts.next().await {
                    let block = part?;
                    root = Some(block.clone());
                    yield block;
                }
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
        .boxed()
    }
}

impl HamtDirectory {
    pub fn encode<'a>(self) -> BoxStream<'a, Result<Block>> {
        self.hamt.encode()
    }
}

enum Content {
    Reader(Pin<Box<dyn AsyncRead + Send>>),
    Path(PathBuf),
}

impl Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Content::Reader(_) => write!(f, "Content::Reader(Pin<Box<dyn AsyncRead + Send>>)"),
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
        Directory::single("".into(), Entry::File(self))
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
        Directory::single("".into(), Entry::Symlink(self))
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

/// Representation of a raw block
#[derive(Debug, PartialEq, Eq)]
pub struct RawBlock {
    name: String,
    block: Block,
}

impl RawBlock {
    pub fn new(name: &str, block: Block) -> Self {
        RawBlock {
            name: name.to_string(),
            block,
        }
    }
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn into_block(self) -> Block {
        self.block
    }

    pub fn wrap(self) -> Directory {
        Directory::single("".into(), Entry::RawBlock(self))
    }

    pub fn encode(self) -> Result<Block> {
        Ok(self.into_block())
    }
}

/// Constructs a UnixFS file.
pub struct FileBuilder {
    name: Option<String>,
    path: Option<PathBuf>,
    reader: Option<Pin<Box<dyn AsyncRead + Send>>>,
    chunker: Chunker,
    degree: usize,
}

impl Default for FileBuilder {
    fn default() -> Self {
        Self {
            name: None,
            path: None,
            reader: None,
            chunker: Chunker::Fixed(chunker::Fixed::default()),
            degree: DEFAULT_DEGREE,
        }
    }
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
            .field("chunker", &self.chunker)
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

    pub fn name<N: Into<String>>(mut self, name: N) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn chunker(mut self, chunker: Chunker) -> Self {
        self.chunker = chunker;
        self
    }

    /// Set the chunker to be fixed size.
    pub fn fixed_chunker(mut self, chunk_size: usize) -> Self {
        self.chunker = Chunker::Fixed(chunker::Fixed::new(chunk_size));
        self
    }

    /// Use the rabin chunker.
    pub fn rabin_chunker(mut self) -> Self {
        self.chunker = Chunker::Rabin(Box::default());
        self
    }

    pub fn degree(mut self, degree: usize) -> Self {
        self.degree = degree;
        self
    }

    pub fn content_bytes<B: Into<Bytes>>(mut self, content: B) -> Self {
        let bytes = content.into();
        self.reader = Some(Box::pin(std::io::Cursor::new(bytes)));
        self
    }

    pub fn content_reader<T: AsyncRead + Send + 'static>(mut self, content: T) -> Self {
        self.reader = Some(Box::pin(content));
        self
    }

    pub async fn build(self) -> Result<File> {
        let degree = self.degree;
        let chunker = self.chunker;
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
pub enum Entry {
    File(File),
    Directory(Directory),
    Symlink(Symlink),
    RawBlock(RawBlock),
}

impl Entry {
    pub fn name(&self) -> &str {
        match self {
            Entry::File(f) => f.name(),
            Entry::Directory(d) => d.name(),
            Entry::Symlink(s) => s.name(),
            Entry::RawBlock(r) => r.name(),
        }
    }

    pub async fn encode(self) -> Result<BoxStream<'static, Result<Block>>> {
        Ok(match self {
            Entry::File(f) => f.encode().await?.boxed(),
            Entry::Directory(d) => d.encode(),
            Entry::Symlink(s) => stream::iter(Some(s.encode())).boxed(),
            Entry::RawBlock(r) => stream::iter(Some(r.encode())).boxed(),
        })
    }

    pub async fn from_path(path: &Path, config: Config) -> Result<Self> {
        let entry = if path.is_dir() {
            if let Some(chunker_config) = config.chunker {
                let chunker = chunker_config.into();
                let dir = DirectoryBuilder::new()
                    .chunker(chunker)
                    .add_path(path)
                    .await?
                    .build()
                    .await?;
                Entry::Directory(dir)
            } else {
                anyhow::bail!("expected a ChunkerConfig in the Config");
            }
        } else if path.is_file() {
            if let Some(chunker_config) = config.chunker {
                let chunker = chunker_config.into();
                let file = FileBuilder::new()
                    .chunker(chunker)
                    .path(path)
                    .build()
                    .await?;
                Entry::File(file)
            } else {
                anyhow::bail!("expected a ChunkerConfig in the Config");
            }
        } else if path.is_symlink() {
            let symlink = SymlinkBuilder::new(path).build().await?;
            Entry::Symlink(symlink)
        } else {
            anyhow::bail!("can only add files, directories, or symlinks");
        };
        if config.wrap {
            return Ok(Entry::Directory(entry.wrap()));
        }
        Ok(entry)
    }

    fn wrap(self) -> Directory {
        match self {
            Entry::File(f) => f.wrap(),
            Entry::Directory(d) => d.wrap(),
            Entry::Symlink(s) => s.wrap(),
            Entry::RawBlock(r) => r.wrap(),
        }
    }
}

/// Construct a UnixFS directory.
#[derive(Debug)]
pub struct DirectoryBuilder {
    name: Option<String>,
    entries: Vec<Entry>,
    typ: DirectoryType,
    chunker: Chunker,
    degree: usize,
}

impl Default for DirectoryBuilder {
    fn default() -> Self {
        Self {
            name: None,
            entries: Default::default(),
            typ: DirectoryType::Basic,
            chunker: Chunker::Fixed(chunker::Fixed::default()),
            degree: DEFAULT_DEGREE,
        }
    }
}

impl DirectoryBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn hamt(mut self) -> Self {
        self.typ = DirectoryType::Hamt;
        self
    }

    pub fn name<N: Into<String>>(mut self, name: N) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn chunker(mut self, chunker: Chunker) -> Self {
        self.chunker = chunker;
        self
    }

    pub fn degree(mut self, degree: usize) -> Self {
        self.degree = degree;
        self
    }

    pub fn add_dir(self, dir: Directory) -> Result<Self> {
        Ok(self.add_entry(Entry::Directory(dir)))
    }

    pub fn add_file(self, file: File) -> Self {
        self.add_entry(Entry::File(file))
    }

    pub fn add_raw_block(self, raw_block: RawBlock) -> Self {
        self.add_entry(Entry::RawBlock(raw_block))
    }

    pub fn add_symlink(self, symlink: Symlink) -> Self {
        self.add_entry(Entry::Symlink(symlink))
    }

    pub fn add_entry(mut self, entry: Entry) -> Self {
        if self.typ == DirectoryType::Basic && self.entries.len() >= DIRECTORY_LINK_LIMIT {
            self.typ = DirectoryType::Hamt
        }
        self.entries.push(entry);
        self
    }

    pub fn add_entries(mut self, entries: impl Iterator<Item = Entry>) -> Self {
        for entry in entries {
            self = self.add_entry(entry);
        }
        self
    }

    pub async fn add_path(self, path: impl Into<PathBuf>) -> Result<Self> {
        let chunker = self.chunker.clone();
        let degree = self.degree.clone();
        Ok(self.add_entries(
            make_entries_from_path(path, chunker, degree)
                .await?
                .into_iter(),
        ))
    }

    pub async fn build(self) -> Result<Directory> {
        let DirectoryBuilder {
            name, entries, typ, ..
        } = self;

        let name = name.unwrap_or_default();
        Ok(match typ {
            DirectoryType::Basic => Directory::Basic(BasicDirectory { name, entries }),
            DirectoryType::Hamt => {
                let hamt = HamtNode::new(entries)
                    .context("unable to build hamt. Probably a hash collision.")?;
                Directory::Hamt(HamtDirectory {
                    name,
                    hamt: Box::new(hamt),
                })
            }
        })
    }
}

/// A leaf when building a hamt directory.
///
/// Basically just an entry and the hash of its name.
#[derive(Debug, PartialEq)]
pub struct HamtLeaf([u8; 8], Entry);

/// A node when building a hamt directory.
///
/// Either a branch or a leaf. Root will always be a branch,
/// even if it has only one child.
#[derive(Debug, PartialEq)]
enum HamtNode {
    Branch(BTreeMap<u32, HamtNode>),
    Leaf(HamtLeaf),
}

impl HamtNode {
    fn new(entries: Vec<Entry>) -> anyhow::Result<HamtNode> {
        // add the hash
        let entries = entries
            .into_iter()
            .map(|entry| {
                let name = entry.name().to_string();
                let hash = hash_key(name.as_bytes());
                HamtLeaf(hash, entry)
            })
            .collect::<Vec<_>>();
        Self::group(entries, 0, 8)
    }

    fn group(leafs: Vec<HamtLeaf>, pos: u32, len: u32) -> anyhow::Result<HamtNode> {
        Ok(if leafs.len() == 1 && pos > 0 {
            HamtNode::Leaf(leafs.into_iter().next().unwrap())
        } else {
            let mut res = BTreeMap::<u32, Vec<HamtLeaf>>::new();
            for leaf in leafs {
                let value = bits(&leaf.0, pos, len)?;
                res.entry(value).or_default().push(leaf);
            }
            let res = res
                .into_iter()
                .map(|(key, leafs)| {
                    let node = Self::group(leafs, pos + len, len)?;
                    anyhow::Ok((key, node))
                })
                .collect::<anyhow::Result<_>>()?;
            HamtNode::Branch(res)
        })
    }

    fn name(&self) -> &str {
        match self {
            HamtNode::Branch(_) => "",
            HamtNode::Leaf(HamtLeaf(_, entry)) => entry.name(),
        }
    }

    pub fn encode<'a>(self) -> BoxStream<'a, Result<Block>> {
        match self {
            Self::Branch(tree) => {
                async_stream::try_stream! {
                    let mut links = Vec::with_capacity(tree.len());
                    let mut bitfield = Bitfield::default();
                    for (prefix, node) in tree {
                        let name = format!("{:02X}{}", prefix, node.name());
                        bitfield.set_bit(prefix);
                        let blocks = node.encode();
                        let mut root = None;
                        tokio::pin!(blocks);
                        while let Some(block) = blocks.next().await {
                            let block = block?;
                            root = Some(*block.cid());
                            yield block;
                        }
                        links.push(crate::unixfs::dag_pb::PbLink {
                            name: Some(name),
                            hash: root.map(|cid| cid.to_bytes()),
                            tsize: None,
                        });
                    }
                    let inner = unixfs_pb::Data {
                        r#type: DataType::HamtShard as i32,
                        hash_type: Some(HamtHashFunction::Murmur3 as u64),
                        fanout: Some(256),
                        data: Some(bitfield.as_bytes().to_vec().into()),
                        ..Default::default()
                    };
                    let outer = encode_unixfs_pb(&inner, links).unwrap();
                    // it does not really matter what enum variant we choose here as long as
                    // it is not raw. The type of the node will be HamtShard from above.
                    let node = UnixfsNode::Directory(crate::unixfs::Node { outer, inner });
                    yield node.encode()?;
                }
                .boxed()
            }
            Self::Leaf(HamtLeaf(_hash, entry)) => async move { entry.encode().await }
                .try_flatten_stream()
                .boxed(),
        }
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

/// Configuration for adding unixfs content
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Should the outer object be wrapped in a directory?
    pub wrap: bool,
    pub chunker: Option<ChunkerConfig>,
}

#[async_recursion(?Send)]
async fn make_entries_from_path<P: Into<PathBuf>>(
    path: P,
    chunker: Chunker,
    degree: usize,
) -> Result<Vec<Entry>> {
    let mut directory_reader = tokio::fs::read_dir(path.into()).await?;
    let mut entries = vec![];
    while let Some(entry) = directory_reader.next_entry().await? {
        let path = entry.path();
        if path.is_symlink() {
            entries.push(Entry::Symlink(SymlinkBuilder::new(path).build().await?))
        } else if path.is_file() {
            entries.push(Entry::File(
                FileBuilder::new()
                    .chunker(chunker.clone())
                    .degree(degree)
                    .path(path)
                    .build()
                    .await?,
            ));
        } else if path.is_dir() {
            entries.push(Entry::Directory(
                DirectoryBuilder::new()
                    .name(
                        path.file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or_default(),
                    )
                    .add_entries(
                        make_entries_from_path(path, chunker.clone(), degree)
                            .await?
                            .into_iter(),
                    )
                    .build()
                    .await?,
            ))
        } else {
            anyhow::bail!("directory entry is neither file nor directory nor symlink")
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunker::DEFAULT_CHUNKS_SIZE;
    use futures::TryStreamExt;
    use std::io::Write;

    #[tokio::test]
    async fn test_builder_basics() -> Result<()> {
        // Create a directory
        let dir = DirectoryBuilder::new().name("foo");

        // Add a file
        let bar = FileBuilder::new()
            .name("bar.txt")
            .content_bytes(b"bar".to_vec())
            .build()
            .await?;
        let bar_encoded: Vec<_> = {
            let bar = FileBuilder::new()
                .name("bar.txt")
                .content_bytes(b"bar".to_vec())
                .build()
                .await?;
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

        let dir = dir.add_file(bar).add_symlink(baz).build().await?;

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
        let dir = DirectoryBuilder::new().build().await?;

        DirectoryBuilder::new()
            .add_dir(dir)
            .expect("recursive directories allowed");
        Ok(())
    }

    #[tokio::test]
    async fn test_builder_stream_small() -> Result<()> {
        // Create a directory
        let dir = DirectoryBuilder::new().name("foo");

        // Add a file
        let bar_reader = std::io::Cursor::new(b"bar");
        let bar = FileBuilder::new()
            .name("bar.txt")
            .content_reader(bar_reader)
            .build()
            .await?;
        let bar_encoded: Vec<_> = {
            let bar_reader = std::io::Cursor::new(b"bar");
            let bar = FileBuilder::new()
                .name("bar.txt")
                .content_reader(bar_reader)
                .build()
                .await?;
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

        let dir = dir.add_file(bar).add_symlink(baz).build().await?;

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
    #[cfg(not(windows))]
    #[tokio::test]
    async fn symlink_from_disk_test() -> Result<()> {
        let temp_dir = ::tempfile::tempdir()?;
        let expect_name = "path_to_symlink";
        let expect_target = temp_dir.path().join("path_to_target");
        let expect_path = temp_dir.path().join(expect_name);

        tokio::fs::symlink(expect_target.clone(), expect_path.clone()).await?;

        let got_symlink = SymlinkBuilder::new(expect_path).build().await?;
        assert_eq!(expect_name, got_symlink.name());
        assert_eq!(expect_target, got_symlink.target);
        Ok(())
    }
    #[tokio::test]
    async fn test_builder_stream_large() -> Result<()> {
        // Create a directory
        let dir = DirectoryBuilder::new().name("foo");

        // Add a file
        let bar_reader = std::io::Cursor::new(vec![1u8; 1024 * 1024]);
        let bar = FileBuilder::new()
            .name("bar.txt")
            .content_reader(bar_reader)
            .build()
            .await?;
        let bar_encoded: Vec<_> = {
            let bar_reader = std::io::Cursor::new(vec![1u8; 1024 * 1024]);
            let bar = FileBuilder::new()
                .name("bar.txt")
                .content_reader(bar_reader)
                .build()
                .await?;
            bar.encode().await?.try_collect().await?
        };
        assert_eq!(bar_encoded.len(), 5);

        // Add a file
        let mut baz_content = Vec::with_capacity(1024 * 1024 * 2);
        for i in 0..2 {
            for _ in 0..(1024 * 1024) {
                baz_content.push(i);
            }
        }

        let baz_reader = std::io::Cursor::new(baz_content.clone());
        let baz = FileBuilder::new()
            .name("baz.txt")
            .content_reader(baz_reader)
            .build()
            .await?;
        let baz_encoded: Vec<_> = {
            let baz_reader = std::io::Cursor::new(baz_content);
            let baz = FileBuilder::new()
                .name("baz.txt")
                .content_reader(baz_reader)
                .build()
                .await?;
            baz.encode().await?.try_collect().await?
        };
        assert_eq!(baz_encoded.len(), 9);

        let dir = dir.add_file(bar).add_file(baz).build().await?;

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
                assert!(node.size().unwrap() > 0);
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
        let builder = DirectoryBuilder::new().hamt();
        assert_eq!(DirectoryType::Hamt, builder.typ);

        let mut builder = DirectoryBuilder::new();

        for _i in 0..DIRECTORY_LINK_LIMIT {
            let file = FileBuilder::new()
                .name("foo.txt")
                .content_bytes(Bytes::from("hello world"))
                .build()
                .await?;
            builder = builder.add_file(file);
        }

        // under DIRECTORY_LINK_LIMIT should still be a basic directory
        assert_eq!(DirectoryType::Basic, builder.typ);

        let file = FileBuilder::new()
            .name("foo.txt")
            .content_bytes(Bytes::from("hello world"))
            .build()
            .await?;
        builder = builder.add_file(file);

        // at directory link limit should be processed as a hamt
        assert_eq!(DirectoryType::Hamt, builder.typ);
        Ok(())
    }

    #[tokio::test]
    async fn test_hamt_hash_collision() -> Result<()> {
        // allow hamt override
        let mut builder = DirectoryBuilder::new().hamt();
        for _i in 0..2 {
            let file = FileBuilder::new()
                .name("foo.txt")
                .content_bytes(Bytes::from("hello world"))
                .build()
                .await?;
            builder = builder.add_file(file);
        }
        assert!(builder.build().await.is_err());
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
        let nested_dir = Directory::single(
            String::from(
                nested_dir_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap(),
            ),
            Entry::File(nested_file),
        );

        let file = FileBuilder::new().path(file_path).build().await?;

        let expected = Directory::basic(
            String::from(dir.clone().file_name().and_then(|s| s.to_str()).unwrap()),
            vec![Entry::File(file), Entry::Directory(nested_dir)],
        );

        let got = DirectoryBuilder::new()
            .add_entries(
                make_entries_from_path(
                    dir,
                    Chunker::Fixed(chunker::Fixed::default()),
                    DEFAULT_DEGREE,
                )
                .await?
                .into_iter(),
            )
            .build()
            .await?;

        let basic_entries = |dir: Directory| match dir {
            Directory::Basic(basic) => basic.entries,
            _ => panic!("expected directory"),
        };

        // Before comparison sort entries to make test deterministic.
        // The readdir_r function is used in the underlying platform which
        // gives no guarantee to return in a specific order.
        // https://stackoverflow.com/questions/40021882/how-to-sort-readdir-iterator
        let expected = basic_entries(expected);
        let mut got = basic_entries(got);
        got.sort_by_key(|entry| entry.name().to_string());
        assert_eq!(expected, got);
        Ok(())
    }

    #[test]
    fn test_chunk_config_from_str() {
        assert_eq!(
            "fixed".parse::<ChunkerConfig>().unwrap(),
            ChunkerConfig::Fixed(DEFAULT_CHUNKS_SIZE)
        );
        assert_eq!(
            "fixed-123".parse::<ChunkerConfig>().unwrap(),
            ChunkerConfig::Fixed(123)
        );

        assert!("fixed-".parse::<ChunkerConfig>().is_err());
        assert!(format!("fixed-{}", DEFAULT_CHUNK_SIZE_LIMIT + 1)
            .parse::<ChunkerConfig>()
            .is_err());
        assert!("foo-123".parse::<ChunkerConfig>().is_err());
        assert!("foo".parse::<ChunkerConfig>().is_err());

        assert_eq!(
            "rabin".parse::<ChunkerConfig>().unwrap(),
            ChunkerConfig::Rabin
        );
    }
}
