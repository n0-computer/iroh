use std::io::{Cursor, Read, Seek, self};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use cid::Cid;
use libipld::error::{InvalidMultihash, UnsupportedMultihash};
use multihash::{Code, MultihashDigest};
use pin_project::pin_project;
use serde::{Serialize, Deserialize};
use tokio::io::AsyncRead;

use crate::{codecs::Codec, parse_links, unixfs::dag_pb};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReference {
    path: String,
    offset: u64,
    len: usize,
}

/// Data with optional provenance
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytesWithProvenance {
    pub data: Bytes,
    pub provenance: Option<FileReference>,
}

impl BytesWithProvenance {
    pub fn new(data: Bytes, provenance: Option<FileReference>) -> Self {
        Self { data, provenance }
    }
}

impl From<Bytes> for BytesWithProvenance {
    fn from(data: Bytes) -> Self {
        Self {
            data,
            provenance: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BytesOrReference {
    Bytes(Bytes),
    Reference(FileReference),
}

impl From<BytesWithProvenance> for BytesOrReference {
    fn from(value: BytesWithProvenance) -> Self {
        match value.provenance {
            Some(reference) => Self::Reference(reference),
            None => Self::Bytes(value.data),
        }
    }
}

impl BytesOrReference {
    pub fn size(&self) -> usize {
        match self {
            BytesOrReference::Bytes(b) => b.len(),
            BytesOrReference::Reference(r) => r.len,
        }
    }

    /// load the data from disk, in case the block is a reference
    pub fn load(&self) -> io::Result<Bytes> {
        match self {
            BytesOrReference::Bytes(b) => Ok(b.clone()),
            BytesOrReference::Reference(r) => {
                let mut file = std::fs::File::open(&r.path)?;
                file.seek(std::io::SeekFrom::Start(r.offset))?;
                let mut buf = vec![0; r.len];
                file.read_exact(&mut buf)?;
                Ok(Bytes::from(buf))
            }
        }
    }
}


/// Wrap a reader with optional provenance
#[pin_project]
#[derive(Debug)]
pub struct ReaderWithProvenance<R> {
    #[pin]
    inner: R,
    provenance: Option<String>,
    offset: u64,
}

impl<R> ReaderWithProvenance<R> {
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn new(reader: R, provenance: Option<String>) -> Self {
        Self {
            inner: reader,
            offset: 0,
            provenance,
        }
    }

    /// Given a buffer that is assumed to be ending at the current stream position, enhance it with
    /// the provenance information (path and offset/len)
    pub fn enhance(&self, buffer: Bytes) -> BytesWithProvenance {
        let provenance = self.provenance.as_ref().map(|p| FileReference {
            path: p.clone(),
            offset: self.offset - buffer.len() as u64,
            len: buffer.len(),
        });
        BytesWithProvenance::new(buffer, provenance)
    }
}

impl<R> From<R> for ReaderWithProvenance<R> {
    fn from(reader: R) -> Self {
        Self::new(reader, None)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ReaderWithProvenance<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        let o0 = buf.filled().len() as u64;
        match this.inner.poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                let o1 = buf.filled().len() as u64;
                *this.offset += o1 - o0;
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    cid: Cid,
    links: Vec<Cid>,
    data: BytesOrReference,
}

impl Block {
    pub fn new(cid: Cid, data: BytesOrReference, links: Vec<Cid>) -> Self {
        Self { cid, links, data }
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn load(&self) -> io::Result<Bytes> {
        self.data.load()
    }

    pub fn size(&self) -> usize {
        self.data.size()
    }

    pub fn links(&self) -> &[Cid] {
        &self.links
    }

    pub fn raw_data_size(&self) -> Option<u64> {
        let codec = Codec::try_from(self.cid.codec()).unwrap();
        match codec {
            Codec::Raw => Some(self.data.size() as u64),
            _ => None,
        }
    }

    /// Validate the block. Will return an error if the hash or the links are wrong.
    pub fn validate(&self) -> Result<()> {
        // check that the cid is supported
        let code = self.cid.hash().code();
        let data = self.load()?;
        let mh = Code::try_from(code)
            .map_err(|_| UnsupportedMultihash(code))?
            .digest(&data);
        // check that the hash matches the data
        if mh.digest() != self.cid.hash().digest() {
            return Err(InvalidMultihash(mh.to_bytes()).into());
        }
        // check that the links are complete
        let expected_links = parse_links(&self.cid, &data)?;
        let mut actual_links = self.links.clone();
        actual_links.sort();
        // TODO: why do the actual links need to be deduplicated?
        actual_links.dedup();
        anyhow::ensure!(expected_links == actual_links, "links do not match");
        Ok(())
    }

    pub fn into_parts(self) -> (Cid, BytesOrReference, Vec<Cid>) {
        (self.cid, self.data, self.links)
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
