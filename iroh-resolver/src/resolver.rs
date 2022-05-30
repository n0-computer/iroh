use std::fmt::{self, Display, Formatter};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::multihash::{Code, MultihashDigest};
use cid::Cid;
use iroh_rpc_client::Client;
use libipld::codec::{Decode, Encode};
use libipld::prelude::Codec as _;
use libipld::{Ipld, IpldCodec};
use tokio::io::AsyncRead;
use tracing::{debug, trace, warn};

use crate::codecs::Codec;
use crate::unixfs::{poll_read_buf_at_pos, DataType, LinkRef, UnixfsNode, UnixfsReader};

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

    pub fn extend_tail(&mut self, tail: Vec<String>) {
        self.tail.extend(tail);
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
            CidOrDomain::Cid(c) => c.fmt(f),
            CidOrDomain::Domain(s) => s.fmt(f),
        }
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "/{}/{}", self.typ.as_str(), self.root)?;

        for part in &self.tail {
            write!(f, "/{}", part)?;
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

        let tail = parts.map(Into::into).collect();

        Ok(Path { typ, root, tail })
    }
}

#[derive(Debug)]
pub struct Out {
    metadata: Metadata,
    content: OutContent,
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

    /// What kind of content this is this.
    pub fn typ(&self) -> OutType {
        self.content.typ()
    }

    /// Returns an iterator over the content of this directory.
    /// Only if this is of type `unixfs` and a directory.
    pub fn unixfs_read_dir(&self) -> Option<impl Iterator<Item = Result<LinkRef<'_>>>> {
        match self.content {
            OutContent::Unixfs(ref node) => {
                if node.is_dir() {
                    Some(node.links())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
enum OutContent {
    DagPb(Ipld, Bytes),
    Unixfs(UnixfsNode),
    DagCbor(Ipld, Bytes),
    DagJson(Ipld, Bytes),
    Raw(Ipld, Bytes),
}

impl OutContent {
    fn typ(&self) -> OutType {
        match self {
            OutContent::DagPb(_, _) => OutType::DagPb,
            OutContent::Unixfs(_) => OutType::Unixfs,
            OutContent::DagCbor(_, _) => OutType::DagCbor,
            OutContent::DagJson(_, _) => OutType::DagJson,
            OutContent::Raw(_, _) => OutType::Raw,
        }
    }
}

/// Metadata for the reolution result.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// The original path for that was resolved.
    pub path: Path,
    /// Size in bytes.
    pub size: Option<usize>,
    pub typ: OutType,
    pub unixfs_type: Option<UnixfsType>,
    /// List of mappings "path part" -> Cid.
    ///
    /// Only contains the "top level cids", and only path segments that actually map
    /// to a block.
    pub resolved_path: Vec<(String, Cid)>,
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

pub enum OutPrettyReader<T: ContentLoader> {
    DagPb(usize, Bytes),
    Unixfs(UnixfsReader<T>),
    DagCbor(usize, Bytes),
    DagJson(usize, Bytes),
    Raw(usize, Bytes),
}

impl Out {
    pub fn pretty<T: ContentLoader>(self, loader: T) -> OutPrettyReader<T> {
        let pos = 0;
        match self.content {
            OutContent::DagPb(_, bytes) => OutPrettyReader::DagPb(pos, bytes),
            OutContent::DagCbor(_, bytes) => OutPrettyReader::DagCbor(pos, bytes),
            OutContent::DagJson(_, bytes) => OutPrettyReader::DagJson(pos, bytes),
            OutContent::Raw(_, bytes) => OutPrettyReader::Raw(pos, bytes),
            OutContent::Unixfs(node) => OutPrettyReader::Unixfs(node.pretty(loader)),
        }
    }
}

impl<T: ContentLoader + Unpin + 'static> AsyncRead for OutPrettyReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            OutPrettyReader::DagPb(pos, content)
            | OutPrettyReader::DagCbor(pos, content)
            | OutPrettyReader::DagJson(pos, content)
            | OutPrettyReader::Raw(pos, content) => {
                let res = poll_read_buf_at_pos(pos, content, buf);
                Poll::Ready(res)
            }
            OutPrettyReader::Unixfs(r) => Pin::new(&mut *r).poll_read(cx, buf),
        }
    }
}

#[derive(Debug)]
pub struct Resolver<T: ContentLoader> {
    loader: T,
}

#[async_trait]
pub trait ContentLoader: Sync + Send + std::fmt::Debug + Clone {
    /// Loads the actual content of a given cid.
    async fn load_cid(&self, cid: &Cid) -> Result<Bytes>;
}

#[async_trait]
impl<T: ContentLoader> ContentLoader for Arc<T> {
    async fn load_cid(&self, cid: &Cid) -> Result<Bytes> {
        self.as_ref().load_cid(cid).await
    }
}

#[async_trait]
impl<'a, T: ContentLoader> ContentLoader for &'a T {
    async fn load_cid(&self, cid: &Cid) -> Result<Bytes> {
        (*self).load_cid(cid).await
    }
}

#[async_trait]
impl ContentLoader for Client {
    async fn load_cid(&self, cid: &Cid) -> Result<Bytes> {
        trace!("loading cid");
        // TODO: better strategy

        let cid = *cid;
        match self.store.get(cid).await {
            Ok(Some(data)) => {
                trace!("retrieved from store");
                return Ok(data);
            }
            Ok(None) => {}
            Err(err) => {
                warn!("failed to fetch data from store {}: {:?}", cid, err);
            }
        }

        let providers = self.p2p.fetch_providers(&cid).await?;
        let bytes = self.p2p.fetch_bitswap(cid, providers).await?;

        // TODO: is this the right place?
        // verify cid
        let bytes_clone = bytes.clone();
        match tokio::task::spawn_blocking(move || verify_hash(&cid, &bytes_clone)).await? {
            Some(true) => {
                // all good
            }
            Some(false) => {
                bail!("invalid hash {:?}", cid.hash());
            }
            None => {
                warn!(
                    "unable to verify hash, unknown hash function {} for {}",
                    cid.hash().code(),
                    cid
                );
            }
        }

        // trigger storage in the background
        let cloned = bytes.clone();
        let rpc = self.clone();
        tokio::spawn(async move {
            let clone2 = cloned.clone();
            let links =
                tokio::task::spawn_blocking(move || parse_links(&cid, &clone2).unwrap_or_default())
                    .await
                    .unwrap_or_default();

            let len = cloned.len();
            let links_len = links.len();
            match rpc.store.put(cid, cloned, links).await {
                Ok(_) => debug!("stored {} ({}bytes, {}links)", cid, len, links_len),
                Err(err) => {
                    warn!("failed to store {}: {:?}", cid, err);
                }
            }
        });

        trace!("retrieved from p2p");

        Ok(bytes)
    }
}

impl<T: ContentLoader> Resolver<T> {
    pub fn new(loader: T) -> Self {
        Resolver { loader }
    }

    /// Resolves through a given path, returning the [`Cid`] and raw bytes of the final leaf.
    #[tracing::instrument(skip(self))]
    pub async fn resolve(&self, path: Path) -> Result<Out> {
        // Resolve the root block.
        let (root_cid, root_bytes) = self.resolve_root(&path).await?;

        let codec = Codec::try_from(root_cid.codec()).context("unknown codec")?;
        match codec {
            Codec::DagPb => {
                self.resolve_dag_pb_or_unixfs(path, root_cid, root_bytes)
                    .await
            }
            Codec::DagCbor => self.resolve_dag_cbor(path, root_cid, root_bytes).await,
            Codec::DagJson => self.resolve_dag_json(path, root_cid, root_bytes).await,
            Codec::Raw => self.resolve_raw(path, root_cid, root_bytes).await,
            _ => bail!("unsupported codec {:?}", codec),
        }
    }

    async fn inner_resolve(
        &self,
        current: &mut UnixfsNode,
        resolved_path: &mut Vec<(String, Cid)>,
        part: &str,
    ) -> Result<()> {
        match current.typ() {
            Some(DataType::Directory) => {
                let next_link = current
                    .get_link_by_name(&part)
                    .await?
                    .ok_or_else(|| anyhow!("link {} not found", part))?;
                let next_bytes = self.load_cid(&next_link.cid).await?;
                let next_node = UnixfsNode::decode(&next_link.cid, next_bytes)?;
                resolved_path.push((part.to_string(), next_link.cid));

                *current = next_node;
            }
            ty => {
                bail!("unexpected unixfs type {:?}", ty);
            }
        }

        Ok(())
    }

    /// Resolves through both DagPb and nested UnixFs DAGs.
    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_dag_pb_or_unixfs(
        &self,
        root_path: Path,
        cid: Cid,
        bytes: Bytes,
    ) -> Result<Out> {
        if let Ok(node) = UnixfsNode::decode(&cid, bytes.clone()) {
            let tail = &root_path.tail;
            let mut current = node;
            let mut resolved_path = vec![(root_path.root.to_string(), cid)];

            for part in tail {
                self.inner_resolve(&mut current, &mut resolved_path, part)
                    .await?;
            }

            let unixfs_type = current.typ().and_then(|t| match t {
                DataType::Directory => Some(UnixfsType::Dir),
                DataType::File | DataType::Raw => Some(UnixfsType::File),
                DataType::Symlink => Some(UnixfsType::Symlink),
                _ => None,
            });
            let metadata = Metadata {
                path: root_path,
                size: current.size(),
                typ: OutType::Unixfs,
                unixfs_type,
                resolved_path,
            };
            Ok(Out {
                metadata,
                content: OutContent::Unixfs(current),
            })
        } else {
            self.resolve_dag_pb(root_path, cid, bytes).await
        }
    }

    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_dag_pb(&self, root_path: Path, cid: Cid, bytes: Bytes) -> Result<Out> {
        let ipld: libipld::Ipld = libipld::IpldCodec::DagPb
            .decode(&bytes)
            .map_err(|e| anyhow!("invalid dag cbor: {:?}", e))?;

        let out = self
            .resolve_ipld(cid, libipld::IpldCodec::DagPb, ipld, &root_path.tail)
            .await?;

        // reencode if we only return part of the original
        let bytes = if root_path.tail.is_empty() {
            bytes
        } else {
            let mut bytes = Vec::new();
            out.encode(libipld::IpldCodec::DagCbor, &mut bytes)?;
            bytes.into()
        };

        let metadata = Metadata {
            path: root_path,
            size: Some(bytes.len()),
            typ: OutType::DagPb,
            unixfs_type: None,
            resolved_path: vec![(cid.to_string(), cid)],
        };
        Ok(Out {
            metadata,
            content: OutContent::DagPb(out, bytes),
        })
    }

    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_dag_cbor(&self, root_path: Path, cid: Cid, bytes: Bytes) -> Result<Out> {
        let ipld: libipld::Ipld = libipld::IpldCodec::DagCbor
            .decode(&bytes)
            .map_err(|e| anyhow!("invalid dag cbor: {:?}", e))?;

        let out = self
            .resolve_ipld(cid, libipld::IpldCodec::DagCbor, ipld, &root_path.tail)
            .await?;

        // reencode if we only return part of the original
        let bytes = if root_path.tail.is_empty() {
            bytes
        } else {
            let mut bytes = Vec::new();
            out.encode(libipld::IpldCodec::DagCbor, &mut bytes)?;
            bytes.into()
        };

        let metadata = Metadata {
            path: root_path,
            size: Some(bytes.len()),
            typ: OutType::DagCbor,
            unixfs_type: None,
            resolved_path: vec![(cid.to_string(), cid)],
        };
        Ok(Out {
            metadata,
            content: OutContent::DagCbor(out, bytes),
        })
    }

    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_dag_json(&self, root_path: Path, cid: Cid, bytes: Bytes) -> Result<Out> {
        let ipld: libipld::Ipld = libipld::IpldCodec::DagJson
            .decode(&bytes)
            .map_err(|e| anyhow!("invalid dag json: {:?}", e))?;

        let out = self
            .resolve_ipld(cid, libipld::IpldCodec::DagJson, ipld, &root_path.tail)
            .await?;

        // reencode if we only return part of the original
        let bytes = if root_path.tail.is_empty() {
            bytes
        } else {
            let mut bytes = Vec::new();
            out.encode(libipld::IpldCodec::DagJson, &mut bytes)?;
            bytes.into()
        };

        let metadata = Metadata {
            path: root_path,
            size: Some(bytes.len()),
            typ: OutType::DagJson,
            unixfs_type: None,
            resolved_path: vec![(cid.to_string(), cid)],
        };
        Ok(Out {
            metadata,
            content: OutContent::DagJson(out, bytes),
        })
    }

    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_raw(&self, root_path: Path, cid: Cid, bytes: Bytes) -> Result<Out> {
        let ipld: libipld::Ipld = libipld::IpldCodec::Raw
            .decode(&bytes)
            .map_err(|e| anyhow!("invalid raw: {:?}", e))?;

        let out = self
            .resolve_ipld(cid, libipld::IpldCodec::Raw, ipld, &root_path.tail)
            .await?;

        let metadata = Metadata {
            path: root_path,
            size: Some(bytes.len()),
            typ: OutType::Raw,
            unixfs_type: None,
            resolved_path: vec![(cid.to_string(), cid)],
        };
        Ok(Out {
            metadata,
            content: OutContent::Raw(out, bytes),
        })
    }

    #[tracing::instrument(skip(self))]
    async fn resolve_ipld(
        &self,
        _cid: Cid,
        codec: libipld::IpldCodec,
        root: Ipld,
        path: &[String],
    ) -> Result<Ipld> {
        let mut root = root;
        let mut current = &root;

        for part in path {
            if let libipld::Ipld::Link(c) = current {
                let c = *c;
                let new_codec: libipld::IpldCodec = c.codec().try_into()?;
                ensure!(
                    new_codec == codec,
                    "can only resolve the same codec {:?} != {:?}",
                    new_codec,
                    codec
                );

                // resolve link and update if we have encountered a link
                let bytes = self.load_cid(&c).await?;
                root = codec
                    .decode(&bytes)
                    .map_err(|e| anyhow!("invalid dag json: {:?}", e))?;
                current = &root;
            }

            let index: libipld::ipld::IpldIndex = if let Ok(i) = part.parse::<usize>() {
                i.into()
            } else {
                part.clone().into()
            };

            current = current.get(index)?;
        }

        // TODO: can we avoid this clone?

        Ok(current.clone())
    }

    #[tracing::instrument(skip(self))]
    async fn resolve_root(&self, root: &Path) -> Result<(Cid, Bytes)> {
        let mut current = root.clone();

        // maximum cursion of ipns lookups
        const MAX_LOOKUPS: usize = 16;

        for _ in 0..MAX_LOOKUPS {
            match current.typ {
                PathType::Ipfs => match current.root {
                    CidOrDomain::Cid(ref c) => return Ok((*c, self.load_cid(c).await?)),
                    CidOrDomain::Domain(_) => bail!("invalid domain encountered"),
                },
                PathType::Ipns => match current.root {
                    CidOrDomain::Cid(ref c) => {
                        let c = self.load_ipns_record(c).await?;
                        current = Path::from_cid(c);
                    }
                    CidOrDomain::Domain(ref domain) => {
                        let mut records = resolve_dnslink(domain).await?;
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
    async fn load_cid(&self, cid: &Cid) -> Result<Bytes> {
        self.loader.load_cid(cid).await
    }

    #[tracing::instrument(skip(self))]
    async fn load_ipns_record(&self, cid: &Cid) -> Result<Cid> {
        todo!()
    }
}

/// Extract links from the given content.
pub fn parse_links(cid: &Cid, bytes: &[u8]) -> Result<Vec<Cid>> {
    let codec = Codec::try_from(cid.codec()).context("unknown codec")?;
    let codec = match codec {
        Codec::DagPb => IpldCodec::DagPb,
        Codec::DagCbor => IpldCodec::DagCbor,
        Codec::DagJson => IpldCodec::DagJson,
        Codec::Raw => IpldCodec::Raw,
        _ => bail!("unsupported codec {:?}", codec),
    };

    let decoded: Ipld = Ipld::decode(codec, &mut std::io::Cursor::new(bytes))?;
    let mut links = Vec::new();
    decoded.references(&mut links);

    Ok(links)
}

/// Verifies that the provided bytes hash to the given multihash.
pub fn verify_hash(cid: &Cid, bytes: &[u8]) -> Option<bool> {
    Code::try_from(cid.hash().code()).ok().map(|code| {
        let calculated_hash = code.digest(bytes);
        &calculated_hash == cid.hash()
    })
}

#[tracing::instrument]
async fn resolve_dnslink(url: &str) -> Result<Vec<Path>> {
    let url = format!("_dnslink.{}.", url);
    let records = resolve_txt_record(&url).await?;
    let records = records
        .into_iter()
        .filter(|r| r.starts_with("dnslink="))
        .map(|r| {
            let p = r.trim_start_matches("dnslink=").trim();
            p.parse()
        })
        .collect::<Result<_>>()?;
    Ok(records)
}

async fn resolve_txt_record(url: &str) -> Result<Vec<String>> {
    use trust_dns_resolver::config::*;
    use trust_dns_resolver::AsyncResolver;

    // Construct a new Resolver with default configuration options
    let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;

    let txt_response = resolver.txt_lookup(url).await?;

    let out = txt_response.into_iter().map(|r| r.to_string()).collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        sync::Arc,
    };

    use super::*;
    use cid::multihash::{Code, MultihashDigest};
    use libipld::{codec::Encode, Ipld, IpldCodec};
    use tokio::io::AsyncReadExt;

    #[async_trait]
    impl ContentLoader for HashMap<Cid, Bytes> {
        async fn load_cid(&self, cid: &Cid) -> Result<Bytes> {
            match self.get(cid) {
                Some(b) => Ok(b.clone()),
                None => bail!("not found"),
            }
        }
    }

    async fn load_fixture(p: &str) -> Bytes {
        Bytes::from(tokio::fs::read(format!("./fixtures/{p}")).await.unwrap())
    }

    async fn read_to_vec<T: AsyncRead + Unpin>(mut reader: T) -> Vec<u8> {
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        out
    }
    async fn read_to_string<T: AsyncRead + Unpin>(reader: T) -> String {
        String::from_utf8(read_to_vec(reader).await).unwrap()
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
            println!("{}", test);
            let p: Path = test.parse().unwrap();
            assert_eq!(p.to_string(), test);
        }

        let valid_tests = [(
            "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
            "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
        )];
        for (test_in, test_out) in valid_tests {
            println!("{}", test_in);
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
            println!("{}", test);
            assert!(test.parse::<Path>().is_err());
        }
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

            assert_eq!(verify_hash(&c, &bytes), Some(true));
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

                let out_bytes = read_to_vec(new_ipld.pretty(loader.clone())).await;
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
                assert_eq!(m.size, Some(out_bytes.len()));
                assert_eq!(m.resolved_path, vec![(c.to_string(), c)]);
            }
            {
                let path = format!("/ipfs/{c}/details/0");
                let new_ipld = resolver.resolve(path.parse().unwrap()).await.unwrap();
                let m = new_ipld.metadata().clone();

                let out_bytes = read_to_vec(new_ipld.pretty(loader.clone())).await;
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
                assert_eq!(m.size, Some(out_bytes.len()));
                assert_eq!(m.resolved_path, vec![(c.to_string(), c)]);
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
                .unixfs_read_dir()
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(ls.len(), 2);
            assert_eq!(ls[0].name.unwrap(), "bar");
            assert_eq!(ls[1].name.unwrap(), "hello.txt");

            let m = ipld_foo.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::Dir));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, None);
            assert_eq!(
                m.resolved_path,
                vec![(root_cid_str.to_string(), root_cid_str.parse().unwrap())]
            );

            if let OutContent::Unixfs(node) = ipld_foo.content {
                assert_eq!(
                    read_to_string(node.pretty(loader.clone())).await,
                    "bar\nhello.txt\n"
                );
            } else {
                panic!("invalid result: {:?}", ipld_foo);
            }
        }

        {
            let path = format!("/ipfs/{root_cid_str}/hello.txt");
            let ipld_hello_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            assert!(ipld_hello_txt.unixfs_read_dir().is_none());

            let m = ipld_hello_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(6));
            assert_eq!(
                m.resolved_path,
                vec![
                    (root_cid_str.to_string(), root_cid_str.parse().unwrap()),
                    ("hello.txt".to_string(), hello_txt_cid_str.parse().unwrap()),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_hello_txt.content {
                assert_eq!(read_to_string(node.pretty(loader.clone())).await, "hello\n");
            } else {
                panic!("invalid result: {:?}", ipld_hello_txt);
            }
        }

        {
            let path = format!("/ipfs/{hello_txt_cid_str}");
            let ipld_hello_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            assert!(ipld_hello_txt.unixfs_read_dir().is_none());

            let m = ipld_hello_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(6));
            assert_eq!(
                m.resolved_path,
                vec![(
                    hello_txt_cid_str.to_string(),
                    hello_txt_cid_str.parse().unwrap()
                )]
            );

            if let OutContent::Unixfs(node) = ipld_hello_txt.content {
                assert_eq!(read_to_string(node.pretty(loader.clone())).await, "hello\n");
            } else {
                panic!("invalid result: {:?}", ipld_hello_txt);
            }
        }

        {
            let path = format!("/ipfs/{root_cid_str}/bar");
            let ipld_bar = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let ls = ipld_bar
                .unixfs_read_dir()
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(ls.len(), 1);
            assert_eq!(ls[0].name.unwrap(), "bar.txt");

            let m = ipld_bar.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::Dir));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, None);
            assert_eq!(
                m.resolved_path,
                vec![
                    (root_cid_str.to_string(), root_cid_str.parse().unwrap()),
                    ("bar".to_string(), bar_cid_str.parse().unwrap()),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar.content {
                assert_eq!(
                    read_to_string(node.pretty(loader.clone())).await,
                    "bar.txt\n"
                );
            } else {
                panic!("invalid result: {:?}", ipld_bar);
            }
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
                    (root_cid_str.to_string(), root_cid_str.parse().unwrap()),
                    ("bar".to_string(), bar_cid_str.parse().unwrap()),
                    ("bar.txt".to_string(), bar_txt_cid_str.parse().unwrap()),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(read_to_string(node.pretty(loader.clone())).await, "world\n");
            } else {
                panic!("invalid result: {:?}", ipld_bar_txt);
            }
        }
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
                .unixfs_read_dir()
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(ls.len(), 2);
            assert_eq!(ls[0].name.unwrap(), "bar");
            assert_eq!(ls[1].name.unwrap(), "hello.txt");

            if let OutContent::Unixfs(node) = ipld_foo.content {
                assert_eq!(
                    read_to_string(node.pretty(loader.clone())).await,
                    "bar\nhello.txt\n"
                );
            } else {
                panic!("invalid result: {:?}", ipld_foo);
            }
        }

        {
            let ipld_hello_txt = resolver
                .resolve(format!("{root_cid_str}/hello.txt").parse().unwrap())
                .await
                .unwrap();

            if let OutContent::Unixfs(node) = ipld_hello_txt.content {
                assert_eq!(read_to_string(node.pretty(loader.clone())).await, "hello\n");
            } else {
                panic!("invalid result: {:?}", ipld_hello_txt);
            }
        }

        {
            let ipld_bar = resolver
                .resolve(format!("{root_cid_str}/bar").parse().unwrap())
                .await
                .unwrap();

            let ls = ipld_bar
                .unixfs_read_dir()
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(ls.len(), 1);
            assert_eq!(ls[0].name.unwrap(), "bar.txt");

            if let OutContent::Unixfs(node) = ipld_bar.content {
                assert_eq!(
                    read_to_string(node.pretty(loader.clone())).await,
                    "bar.txt\n"
                );
            } else {
                panic!("invalid result: {:?}", ipld_bar);
            }
        }

        {
            let ipld_bar_txt = resolver
                .resolve(format!("{root_cid_str}/bar/bar.txt").parse().unwrap())
                .await
                .unwrap();

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(read_to_string(node.pretty(loader.clone())).await, "world\n");
            } else {
                panic!("invalid result: {:?}", ipld_bar_txt);
            }
        }
    }

    #[tokio::test]
    async fn test_unixfs_split_file() {
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
            assert_eq!(m.size, None); // multipart file, we don't know the size ahead of time
            assert_eq!(
                m.resolved_path,
                vec![(root_cid_str.to_string(), root_cid_str.parse().unwrap()),]
            );

            if let OutContent::Unixfs(node) = ipld_readme.content {
                let content = read_to_string(node.pretty(loader.clone())).await;
                print!("{}", content);
                assert_eq!(content.len(), 426);
                assert!(content.starts_with("# iroh"));
                assert!(content.ends_with("</sub>\n\n"));
            } else {
                panic!("invalid result: {:?}", ipld_readme);
            }
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

            assert!(ipld_hello_txt.unixfs_read_dir().is_none());

            let m = ipld_hello_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::File));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(m.size, Some(6));
            assert_eq!(
                m.resolved_path,
                vec![
                    (root_cid_str.to_string(), root_cid_str.parse().unwrap()),
                    ("hello.txt".to_string(), hello_txt_cid_str.parse().unwrap()),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_hello_txt.content {
                assert_eq!(read_to_string(node.pretty(loader.clone())).await, "hello\n");
            } else {
                panic!("invalid result: {:?}", ipld_hello_txt);
            }
        }

        {
            let path = format!("/ipfs/{root_cid_str}/bar");
            let ipld_bar = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let ls = ipld_bar
                .unixfs_read_dir()
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(ls.len(), 4);
            assert_eq!(ls[0].name.unwrap(), "bar.txt");
            assert_eq!(ls[1].name.unwrap(), "my-symlink-local.txt");
            assert_eq!(ls[2].name.unwrap(), "my-symlink-outer.txt");
            assert_eq!(ls[3].name.unwrap(), "my-symlink.txt");
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
                    (root_cid_str.to_string(), root_cid_str.parse().unwrap()),
                    ("bar".to_string(), bar_cid_str.parse().unwrap()),
                    ("bar.txt".to_string(), bar_txt_cid_str.parse().unwrap()),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(read_to_string(node.pretty(loader.clone())).await, "world\n");
            } else {
                panic!("invalid result: {:?}", ipld_bar_txt);
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
                    (root_cid_str.to_string(), root_cid_str.parse().unwrap()),
                    ("bar".to_string(), bar_cid_str.parse().unwrap()),
                    (
                        "my-symlink-local.txt".to_string(),
                        my_symlink_local_cid_str.parse().unwrap()
                    ),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(node.pretty(loader.clone())).await,
                    "./bar.txt"
                );
            } else {
                panic!("invalid result: {:?}", ipld_bar_txt);
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
                    (root_cid_str.to_string(), root_cid_str.parse().unwrap()),
                    ("bar".to_string(), bar_cid_str.parse().unwrap()),
                    (
                        "my-symlink-outer.txt".to_string(),
                        my_symlink_outer_cid_str.parse().unwrap()
                    ),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(node.pretty(loader.clone())).await,
                    "../../hello.txt"
                );
            } else {
                panic!("invalid result: {:?}", ipld_bar_txt);
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
                    (root_cid_str.to_string(), root_cid_str.parse().unwrap()),
                    ("bar".to_string(), bar_cid_str.parse().unwrap()),
                    (
                        "my-symlink.txt".to_string(),
                        my_symlink_cid_str.parse().unwrap()
                    ),
                ]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(node.pretty(loader.clone())).await,
                    "../hello.txt"
                );
            } else {
                panic!("invalid result: {:?}", ipld_bar_txt);
            }

            let path = format!("/ipfs/{my_symlink_cid_str}");
            let ipld_bar_txt = resolver.resolve(path.parse().unwrap()).await.unwrap();

            let m = ipld_bar_txt.metadata();
            assert_eq!(m.unixfs_type, Some(UnixfsType::Symlink));
            assert_eq!(m.path.to_string(), path);
            assert_eq!(m.typ, OutType::Unixfs);
            assert_eq!(
                m.resolved_path,
                vec![(
                    my_symlink_cid_str.to_string(),
                    my_symlink_cid_str.parse().unwrap()
                ),]
            );

            if let OutContent::Unixfs(node) = ipld_bar_txt.content {
                assert_eq!(
                    read_to_string(node.pretty(loader.clone())).await,
                    "../hello.txt"
                );
            } else {
                panic!("invalid result: {:?}", ipld_bar_txt);
            }
        }
    }

    #[tokio::test]
    async fn test_resolve_txt_record() {
        let result = resolve_txt_record("_dnslink.ipfs.io.").await.unwrap();
        assert!(!result.is_empty());
        assert_eq!(result[0], "dnslink=/ipns/website.ipfs.io");

        let result = resolve_txt_record("_dnslink.website.ipfs.io.")
            .await
            .unwrap();
        assert!(!result.is_empty());
        assert!(&result[0].starts_with("dnslink=/ipfs"));
    }

    #[tokio::test]
    async fn test_resolve_dnslink() {
        let result = resolve_dnslink("ipfs.io").await.unwrap();
        assert!(!result.is_empty());
        assert_eq!(result[0], "/ipns/website.ipfs.io".parse().unwrap());

        let result = resolve_dnslink("website.ipfs.io").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].typ(), PathType::Ipfs);
    }
}
