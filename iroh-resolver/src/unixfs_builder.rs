use crate::{
    codecs::Codec,
    unixfs::{dag_pb, unixfs_pb, DataType, UnixfsNode},
};
use anyhow::{anyhow, ensure, Result};
use bytes::{Bytes, BytesMut};
use cid::{multihash::MultihashDigest, Cid};
use prost::Message;
use tokio::io::AsyncReadExt;

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
        let mut links = Vec::with_capacity(self.files.len());
        for file in self.files {
            let (cid, bytes) = file.encode_with_cid()?;
            links.push(dag_pb::PbLink {
                hash: Some(cid.to_bytes()),
                name: Some(file.name),
                tsize: Some(bytes.len() as u64),
            });
        }
        let inner = unixfs_pb::Data {
            r#type: DataType::Directory as i32,
            ..Default::default()
        };
        let data = inner.encode_to_vec().into();
        let outer = dag_pb::PbNode {
            links,
            data: Some(data),
        };

        let node = UnixfsNode::Pb { outer, inner };

        Ok(Directory { node })
    }
}

#[derive(Debug)]
pub struct Directory {
    node: UnixfsNode,
}

impl Directory {
    pub fn encode(&self) -> Result<Bytes> {
        self.node.encode()
    }

    pub fn encode_with_cid(&self) -> Result<(Cid, Bytes)> {
        let bytes = self.node.encode()?;
        let hash = cid::multihash::Code::Sha2_256.digest(&bytes);
        Ok((Cid::new_v1(Codec::Sha2256 as _, hash), bytes))
    }
}

pub struct FileBuilder {
    name: Option<String>,
    content: Option<FileContent>,
}

enum FileContent {
    Bytes(Bytes),
    Reader(Box<dyn tokio::io::AsyncRead + Unpin>, usize),
}

impl FileContent {
    pub async fn into_bytes(self) -> Result<Bytes> {
        match self {
            FileContent::Bytes(v) => Ok(v),
            FileContent::Reader(mut r, l) => {
                let mut bytes = BytesMut::with_capacity(l);
                r.read_exact(&mut bytes).await?;
                Ok(bytes.freeze())
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            FileContent::Bytes(v) => v.len(),
            FileContent::Reader(_, len) => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct File {
    name: String,
    node: UnixfsNode,
}

impl File {
    pub fn encode(&self) -> Result<Bytes> {
        self.node.encode()
    }

    pub fn encode_with_cid(&self) -> Result<(Cid, Bytes)> {
        let bytes = self.node.encode()?;
        let hash = cid::multihash::Code::Sha2_256.digest(&bytes);
        Ok((Cid::new_v1(Codec::Raw as _, hash), bytes))
    }
}

impl FileBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            content: None,
        }
    }

    pub fn name(&mut self, name: impl Into<String>) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    pub fn content_bytes<B: Into<Bytes>>(&mut self, content: B) -> &mut Self {
        self.content = Some(FileContent::Bytes(content.into()));
        self
    }

    pub fn content_reader<T: tokio::io::AsyncRead + Unpin + 'static>(
        &mut self,
        content: T,
        size: usize,
    ) -> &mut Self {
        self.content = Some(FileContent::Reader(Box::new(content), size));
        self
    }

    pub async fn build(self) -> Result<File> {
        // encodes files as raw

        let name = self.name.ok_or_else(|| anyhow!("missing name"))?;
        let content = self.content.ok_or_else(|| anyhow!("missing content"))?;

        // TODO: handle large content
        ensure!(content.len() < 1024 * 1024 * 1024, "file too large");

        let data = content.into_bytes().await?;
        let node = UnixfsNode::Raw { data };

        Ok(File { name, node })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[tokio::test]
    async fn test_builder_basics() -> Result<()> {
        // Create a directory
        let mut dir = DirectoryBuilder::new();
        dir.name("foo");

        // Add a file
        let mut bar = FileBuilder::new();
        bar.name("bar.txt").content_bytes(b"bar".to_vec());
        let bar = bar.build().await?;
        let (bar_cid, _) = bar.encode_with_cid()?;

        // Add a file
        let mut baz = FileBuilder::new();
        baz.name("baz.txt").content_bytes(b"baz".to_vec());
        let baz = baz.build().await?;
        let (baz_cid, _) = baz.encode_with_cid()?;

        dir.add_file(bar).add_file(baz);

        let dir = dir.build().await?;

        let (cid_dir, dir_encoded) = dir.encode_with_cid()?;
        let decoded_dir = UnixfsNode::decode(&cid_dir, dir_encoded)?;
        assert_eq!(dir.node, decoded_dir);

        let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(links[0].name.unwrap(), "bar.txt");
        assert_eq!(links[0].cid, bar_cid);
        assert_eq!(links[1].name.unwrap(), "baz.txt");
        assert_eq!(links[1].cid, baz_cid);

        // TODO: add nested directory

        Ok(())
    }

    // TODO: large files + stream
}
