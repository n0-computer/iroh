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
    balanced_tree::TreeBuilder,
    chunker::{Chunker, DEFAULT_CHUNK_SIZE_LIMIT},
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

    pub async fn encode_root(self) -> Result<(Cid, Bytes)> {
        let mut current = None;
        let parts = self.encode();
        tokio::pin!(parts);

        while let Some(part) = parts.next().await {
            current = Some(part);
        }

        current.expect("must not be empty")
    }

    pub fn encode<'a>(self) -> LocalBoxStream<'a, Result<(Cid, Bytes)>> {
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
                            let (cid, bytes) = part?;
                            root = Some((cid, bytes.clone()));
                            yield (cid, bytes);
                        }
                         (name, root)
                    }
                    Entry::Directory(dir) => {
                        let name = dir.name.clone();
                        let parts = dir.encode();
                        tokio::pin!(parts);
                        let mut root = None;
                        while let Some(part) = parts.next().await {
                            let (cid, bytes) = part?;
                            root = Some((cid, bytes.clone()));
                            yield (cid, bytes);
                        }
                         (name, root)
                    }
                };
                let (cid, bytes) = root.expect("file must not be empty");
                links.push(dag_pb::PbLink {
                    hash: Some(cid.to_bytes()),
                    name: Some(name),
                    tsize: Some(bytes.len() as u64),
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

    pub async fn encode_root(self) -> Result<(Cid, Bytes)> {
        let mut current = None;
        let parts = self.encode().await?;
        tokio::pin!(parts);

        while let Some(part) = parts.next().await {
            current = Some(part);
        }

        current.expect("must not be empty")
    }

    pub async fn encode(self) -> Result<impl Stream<Item = Result<(Cid, Bytes)>>> {
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

/// Constructs a UnixFS file.
#[derive(Default)]
pub struct FileBuilder {
    name: Option<String>,
    path: Option<PathBuf>,
    reader: Option<Pin<Box<dyn AsyncRead>>>,
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
                chunker: Chunker::fixed_size(),
                tree_builder: TreeBuilder::balanced_tree(),
            });
        }

        if let Some(reader) = self.reader {
            let name = self.name.ok_or_else(|| {
                anyhow::anyhow!("must add a name when building a file from a reader or bytes")
            })?;

            return Ok(File {
                content: Content::Reader(reader),
                name,
                chunker: Chunker::fixed_size(),
                tree_builder: TreeBuilder::balanced_tree(),
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
}

/// Construct a UnixFS directory.
#[derive(Debug)]
pub struct DirectoryBuilder {
    name: Option<String>,
    entries: Vec<Entry>,
    typ: DirectoryType,
    recursive: bool,
}

impl Default for DirectoryBuilder {
    fn default() -> Self {
        Self {
            name: None,
            entries: Default::default(),
            typ: DirectoryType::Basic,
            recursive: false,
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

    pub fn recursive(&mut self) -> &mut Self {
        self.recursive = true;
        self
    }

    pub fn name<N: Into<String>>(&mut self, name: N) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    pub fn add_dir(&mut self, dir: Directory) -> Result<&mut Self> {
        ensure!(self.recursive, "recursive directories not allowed");
        Ok(self.entry(Entry::Directory(dir)))
    }

    pub fn add_file(&mut self, file: File) -> &mut Self {
        self.entry(Entry::File(file))
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
pub struct StoreAndProvideClient<'a> {
    pub client: Box<&'a Client>,
}

#[async_trait]
impl<'a> Store for &StoreAndProvideClient<'a> {
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
/// - returns the root Cid
/// - optionally wraps into a UnixFs directory to preserve the filename
pub async fn add_file<S: Store>(store: Option<S>, path: &Path, wrap: bool) -> Result<Cid> {
    ensure!(path.is_file(), "provided path was not a file");

    let file = FileBuilder::new().path(path).build().await?;

    // encode and store
    let mut root = None;

    let parts = {
        if wrap {
            // wrap file in dir to preserve file name
            file.wrap().encode()
        } else {
            Box::pin(file.encode().await?)
        }
    };
    tokio::pin!(parts);

    while let Some(part) = parts.next().await {
        let (cid, bytes) = part?;
        if let Some(ref store) = store {
            store.put(cid, bytes, vec![]).await?;
        }
        root = Some(cid);
    }

    Ok(root.expect("missing root"))
}

/// Adds a directory.
/// - storing the content using `rpc.store`
/// - returns the root Cid
/// - optionally wraps into a UnixFs directory to preserve the directory name
pub async fn add_dir<S: Store>(
    store: Option<S>,
    path: &Path,
    wrap: bool,
    recursive: bool,
) -> Result<Cid> {
    ensure!(path.is_dir(), "provided path was not a directory");

    let dir = make_dir_from_path(path, recursive).await?;
    // encode and store
    let mut root = None;
    let parts = {
        if wrap {
            // wrap dir in dir to preserve file name
            dir.wrap().encode()
        } else {
            dir.encode()
        }
    };
    tokio::pin!(parts);

    while let Some(part) = parts.next().await {
        let (cid, bytes) = part?;
        if let Some(ref store) = store {
            store.put(cid, bytes, vec![]).await?;
        }
        root = Some(cid);
    }

    Ok(root.expect("missing root"))
}

#[async_recursion(?Send)]
async fn make_dir_from_path<P: Into<PathBuf>>(path: P, recursive: bool) -> Result<Directory> {
    let path = path.into();
    let mut dir = DirectoryBuilder::new();
    dir.name(
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default(),
    );
    if recursive {
        dir.recursive();
    }
    let mut directory_reader = tokio::fs::read_dir(path.clone()).await?;
    while let Some(entry) = directory_reader.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            let f = FileBuilder::new().path(path).build().await?;
            dir.add_file(f);
        } else if path.is_dir() {
            let d = make_dir_from_path(path, recursive).await?;
            dir.add_dir(d)?;
        } else {
            anyhow::bail!("directory entry is neither file nor directory")
        }
    }
    dir.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use futures::TryStreamExt;
    use std::io::prelude::*;

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

        // Add a file
        let mut baz = FileBuilder::new();
        baz.name("baz.txt").content_bytes(b"baz".to_vec());
        let baz = baz.build().await?;
        let baz_encoded: Vec<_> = {
            let mut baz = FileBuilder::new();
            baz.name("baz.txt").content_bytes(b"baz".to_vec());
            let baz = baz.build().await?;
            baz.encode().await?.try_collect().await?
        };
        assert_eq!(baz_encoded.len(), 1);

        dir.add_file(bar).add_file(baz);

        let dir = dir.build()?;

        let (cid_dir, dir_encoded) = dir.encode_root().await?;
        let decoded_dir = UnixfsNode::decode(&cid_dir, dir_encoded)?;

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, bar_encoded[0].0);
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, baz_encoded[0].0);

        // TODO: check content
        Ok(())
    }

    #[tokio::test]
    async fn test_recursive_dir_builder() -> Result<()> {
        let dir = DirectoryBuilder::new();
        let dir = dir.build()?;

        let mut no_recursive = DirectoryBuilder::new();
        if no_recursive.add_dir(dir).is_ok() {
            panic!("shouldn't be able to add a directory to a non-recursive directory builder");
        }

        let dir = DirectoryBuilder::new();
        let dir = dir.build()?;

        let mut recursive_dir_builder = DirectoryBuilder::new();
        recursive_dir_builder.recursive();
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

        // Add a file
        let mut baz = FileBuilder::new();
        let baz_reader = std::io::Cursor::new(b"bazz");
        baz.name("baz.txt").content_reader(baz_reader);
        let baz = baz.build().await?;
        let baz_encoded: Vec<_> = {
            let mut baz = FileBuilder::new();
            let baz_reader = std::io::Cursor::new(b"bazz");
            baz.name("baz.txt").content_reader(baz_reader);
            let baz = baz.build().await?;
            baz.encode().await?.try_collect().await?
        };
        assert_eq!(baz_encoded.len(), 1);

        dir.add_file(bar).add_file(baz);

        let dir = dir.build()?;

        let (cid_dir, dir_encoded) = dir.encode_root().await?;
        let decoded_dir = UnixfsNode::decode(&cid_dir, dir_encoded)?;

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, bar_encoded[0].0);
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, baz_encoded[0].0);

        // TODO: check content
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

        let (cid_dir, dir_encoded) = dir.encode_root().await?;
        let decoded_dir = UnixfsNode::decode(&cid_dir, dir_encoded)?;

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, bar_encoded[4].0);
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, baz_encoded[8].0);

        for (i, encoded) in baz_encoded.iter().enumerate() {
            let node = UnixfsNode::decode(&encoded.0, encoded.1.clone())?;
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
            entries: vec![Entry::Directory(nested_dir), Entry::File(file)],
        };

        let got = make_dir_from_path(dir, true).await?;

        assert_eq!(expected, got);

        Ok(())
    }
}
