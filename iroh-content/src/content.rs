use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
    time::Instant,
};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use cid::Cid;
use multihash::{Code, MultihashDigest};

use iroh_metrics::{
    core::{MObserver, MRecorder},
    gateway::{GatewayHistograms, GatewayMetrics},
    observe, record,
};
use libipld::error::{InvalidMultihash, UnsupportedMultihash};

use crate::{codec::Codec, util::parse_links};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    cid: Cid,
    data: Bytes,
    links: Vec<Cid>,
}

impl Block {
    pub fn new(cid: Cid, data: Bytes, links: Vec<Cid>) -> Self {
        Self { cid, data, links }
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    pub fn links(&self) -> &[Cid] {
        &self.links
    }

    pub fn raw_data_size(&self) -> Option<u64> {
        let codec = Codec::try_from(self.cid.codec()).unwrap();
        match codec {
            Codec::Raw => Some(self.data.len() as u64),
            _ => None,
        }
    }

    /// Validate the block. Will return an error if the hash or the links are wrong.
    pub fn validate(&self) -> Result<()> {
        // check that the cid is supported
        let code = self.cid.hash().code();
        let mh = Code::try_from(code)
            .map_err(|_| UnsupportedMultihash(code))?
            .digest(&self.data);
        // check that the hash matches the data
        if mh.digest() != self.cid.hash().digest() {
            return Err(InvalidMultihash(mh.to_bytes()).into());
        }
        // check that the links are complete
        let expected_links = parse_links(&self.cid, &self.data)?;
        let mut actual_links = self.links.clone();
        actual_links.sort();
        // TODO: why do the actual links need to be deduplicated?
        actual_links.dedup();
        anyhow::ensure!(expected_links == actual_links, "links do not match");
        Ok(())
    }

    pub fn into_parts(self) -> (Cid, Bytes, Vec<Cid>) {
        (self.cid, self.data, self.links)
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
