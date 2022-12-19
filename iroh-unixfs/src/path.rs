use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use anyhow::{anyhow, Context};
use cid::Cid;
use iroh_util::codecs::Codec;

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
        let tail = if tail_path != "/" {
            tail_path
                .split(&['/', '\\'])
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        } else {
            vec!["".to_string()]
        };
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

impl From<Path> for iroh_memesync::Path {
    fn from(p: Path) -> Self {
        let root = match p.root {
            CidOrDomain::Cid(root) => root,
            _ => todo!(),
        };

        iroh_memesync::Path { root, tail: p.tail }
    }
}
