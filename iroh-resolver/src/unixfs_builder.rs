use std::pin::Pin;

use crate::{
    chunker::{self, Chunker, DEFAULT_CHUNK_SIZE_LIMIT},
    codecs::Codec,
    unixfs::{dag_pb, unixfs_pb, DataType, UnixfsNode},
};
use anyhow::{anyhow, ensure, Result};
use bytes::Bytes;
use cid::{multihash::MultihashDigest, Cid};
use futures::{Stream, StreamExt};
use prost::Message;
use tokio::io::AsyncRead;

pub struct DirectoryBuilder {
    name: Option<String>,
    files: Vec<File>,
}

impl DirectoryBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            files: Vec::new(),
        }
    }

    pub fn name(&mut self, name: impl Into<String>) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    pub fn add_file(&mut self, file: File) -> &mut Self {
        self.files.push(file);
        self
    }

    pub async fn build(self) -> Result<Directory> {
        let DirectoryBuilder { name, files } = self;
        let name = name.unwrap_or_default();

        Ok(Directory { name, files })
    }
}

pub struct Directory {
    name: String,
    files: Vec<File>,
}

impl Directory {
    pub fn name(&self) -> &str {
        &self.name
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

    pub fn encode(self) -> impl Stream<Item = Result<(Cid, Bytes)>> {
        async_stream::try_stream! {
            let mut links = Vec::new();
            for file in self.files {
                let name = file.name.clone();
                let parts = file.encode();
                tokio::pin!(parts);

                let mut root = None;
                while let Some(part) = parts.next().await {
                    let (cid, bytes) = part?;
                    root = Some((cid, bytes.clone()));
                    yield (cid, bytes);
                }
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

            let node = UnixfsNode::Pb { outer, inner };
            let bytes = node.encode()?;
            let cid = Cid::new_v1(Codec::DagPb as _, cid::multihash::Code::Sha2_256.digest(&bytes));
            yield (cid, bytes)
        }
    }
}

pub struct FileBuilder {
    name: Option<String>,
    content: Option<Pin<Box<dyn AsyncRead>>>,
    chunker: Chunker,
}

pub struct File {
    name: String,
    nodes: Pin<Box<dyn Stream<Item = Result<UnixfsNode>>>>,
}

pub enum EncodedFile {
    Raw(Bytes),
    Chunked { root: Bytes, leaves: Vec<Bytes> },
}

impl EncodedFile {
    pub fn root(&self) -> &Bytes {
        match self {
            EncodedFile::Raw(r) => r,
            EncodedFile::Chunked { root, .. } => root,
        }
    }

    pub fn root_cid(&self) -> Cid {
        let root = self.root();
        let hash = cid::multihash::Code::Sha2_256.digest(root);
        let codec = match self {
            EncodedFile::Raw(_) => Codec::Raw,
            EncodedFile::Chunked { .. } => Codec::Sha2256,
        };

        Cid::new_v1(codec as _, hash)
    }

    pub fn leave_cids(&self) -> Option<Vec<Cid>> {
        match self {
            EncodedFile::Raw(_) => None,
            EncodedFile::Chunked { leaves, .. } => {
                let cids = leaves
                    .iter()
                    .map(|l| Cid::new_v1(Codec::Raw as _, cid::multihash::Code::Sha2_256.digest(l)))
                    .collect();
                Some(cids)
            }
        }
    }
}

impl File {
    pub async fn encode_root(self) -> Result<(Cid, Bytes)> {
        let mut current = None;
        let parts = self.encode();
        tokio::pin!(parts);

        while let Some(part) = parts.next().await {
            current = Some(part);
        }

        current.expect("must not be empty")
    }

    pub fn encode(self) -> impl Stream<Item = Result<(Cid, Bytes)>> {
        async_stream::try_stream! {
            let mut cids = Vec::new();
            let nodes = self.nodes;
            tokio::pin!(nodes);

            while let Some(node) = nodes.next().await {
                let node = node?;
                let bytes = node.encode()?;
                let cid = Cid::new_v1(Codec::Raw as _, cid::multihash::Code::Sha2_256.digest(&bytes));
                cids.push((cid, bytes.len()));
                yield (cid, bytes);
            }

            if cids.len() > 1  {
                // yield root as last element, as we now have all links
                let links = cids.into_iter().map(|(cid, len)| {
                    dag_pb::PbLink {
                        hash: Some(cid.to_bytes()),
                        name: Some("".into()),
                        tsize: Some(len as u64),
                    }
                }).collect();

                let inner = unixfs_pb::Data {
                    r#type: DataType::File as i32,
                    ..Default::default()
                };
                let outer = encode_unixfs_pb(&inner, links)?;
                let node = UnixfsNode::Pb { outer, inner };
                let bytes = node.encode()?;
                let cid = Cid::new_v1(Codec::DagPb as _, cid::multihash::Code::Sha2_256.digest(&bytes));
                yield (cid, bytes)
            }
        }
    }
}

fn encode_unixfs_pb(inner: &unixfs_pb::Data, links: Vec<dag_pb::PbLink>) -> Result<dag_pb::PbNode> {
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

impl FileBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            content: None,
            chunker: chunker::Chunker::fixed_size(),
        }
    }

    pub fn name(&mut self, name: impl Into<String>) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    pub fn content_bytes<B: Into<Bytes>>(&mut self, content: B) -> &mut Self {
        let bytes = content.into();
        self.content = Some(Box::pin(std::io::Cursor::new(bytes)));
        self
    }

    pub fn content_reader<T: tokio::io::AsyncRead + 'static>(&mut self, content: T) -> &mut Self {
        self.content = Some(Box::pin(content));
        self
    }

    pub async fn build(self) -> Result<File> {
        // encodes files as raw

        let name = self.name.ok_or_else(|| anyhow!("missing name"))?;
        let reader = self.content.ok_or_else(|| anyhow!("missing content"))?;

        let nodes = self.chunker.chunks(reader).map(|chunk| match chunk {
            Ok(chunk) => {
                let data = chunk.freeze();
                Ok(UnixfsNode::Raw { data })
            }
            Err(err) => Err(err.into()),
        });

        Ok(File {
            name,
            nodes: Box::pin(nodes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use futures::TryStreamExt;

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
            bar.encode().try_collect().await?
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
            baz.encode().try_collect().await?
        };
        assert_eq!(baz_encoded.len(), 1);

        dir.add_file(bar).add_file(baz);

        let dir = dir.build().await?;

        let (cid_dir, dir_encoded) = dir.encode_root().await?;
        let decoded_dir = UnixfsNode::decode(&cid_dir, dir_encoded)?;

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, bar_encoded[0].0);
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, baz_encoded[0].0);

        // TODO: check content
        // TODO: add nested directory

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
            bar.encode().try_collect().await?
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
            baz.encode().try_collect().await?
        };
        assert_eq!(baz_encoded.len(), 1);

        dir.add_file(bar).add_file(baz);

        let dir = dir.build().await?;

        let (cid_dir, dir_encoded) = dir.encode_root().await?;
        let decoded_dir = UnixfsNode::decode(&cid_dir, dir_encoded)?;

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, bar_encoded[0].0);
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, baz_encoded[0].0);

        // TODO: check content
        // TODO: add nested directory

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
            bar.encode().try_collect().await?
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
            baz.encode().try_collect().await?
        };
        assert_eq!(baz_encoded.len(), 9);

        dir.add_file(bar).add_file(baz);

        let dir = dir.build().await?;

        let (cid_dir, dir_encoded) = dir.encode_root().await?;
        let decoded_dir = UnixfsNode::decode(&cid_dir, dir_encoded)?;

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, bar_encoded[4].0);
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, baz_encoded[8].0);
        for i in 0..9 {
            let node = UnixfsNode::decode(&baz_encoded[i].0, baz_encoded[i].1.clone())?;
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
}
