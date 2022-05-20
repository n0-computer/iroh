use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use cid::multihash::{Code, MultihashDigest};
use cid::Cid;
use iroh_rpc_client::Client;
use libipld::codec::{Decode, Encode};
use libipld::prelude::Codec as _;
use libipld::{Ipld, IpldCodec};
use tracing::{debug, trace, warn};

use crate::codecs::Codec;
use crate::unixfs::{DataType, UnixfsNode};

/// Represents an ipfs path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    typ: PathType,
    root: CidOrDomain,
    tail: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CidOrDomain {
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
pub enum Out {
    DagPb(Ipld),
    Unixfs(UnixfsNode),
    DagCbor(Ipld),
    DagJson(Ipld),
    Raw(Ipld),
}

impl Out {
    pub fn pretty(&self) -> Result<Bytes> {
        match self {
            Out::DagPb(_i) => {
                todo!()
            }
            Out::Unixfs(node) => node.pretty(),
            Out::DagCbor(_i) => {
                todo!()
            }
            Out::DagJson(i) => {
                let mut bytes = Vec::new();
                i.encode(IpldCodec::DagJson, &mut bytes)?;
                Ok(bytes.into())
            }
            Out::Raw(i) => {
                let mut bytes = Vec::new();
                i.encode(IpldCodec::Raw, &mut bytes)?;
                Ok(bytes.into())
            }
        }
    }
}

#[derive(Debug)]
pub struct Resolver {
    rpc: Client,
}

impl Resolver {
    pub fn new(rpc: Client) -> Self {
        Resolver { rpc }
    }

    /// Resolves through a given path, returning the [`Cid`] and raw bytes of the final leaf.
    #[tracing::instrument(skip(self))]
    pub async fn resolve(&self, path: Path) -> Result<Out> {
        // Resolve the root block.
        let (root_cid, root_bytes) = self.resolve_root(path.typ, &path.root).await?;

        let codec = Codec::try_from(root_cid.codec()).context("unknown codec")?;
        match codec {
            Codec::DagPb => {
                self.resolve_dag_pb_or_unixfs(root_cid, root_bytes, path.tail)
                    .await
            }
            Codec::DagCbor => self.resolve_dag_cbor(root_cid, root_bytes, path.tail).await,
            Codec::DagJson => self.resolve_dag_json(root_cid, root_bytes, path.tail).await,
            Codec::Raw => self.resolve_raw(root_cid, root_bytes, path.tail).await,
            _ => bail!("unsupported codec {:?}", codec),
        }
    }

    /// Resolves through both DagPb and nested UnixFs DAGs.
    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_dag_pb_or_unixfs(
        &self,
        cid: Cid,
        bytes: Bytes,
        path: Vec<String>,
    ) -> Result<Out> {
        if let Ok(node) = UnixfsNode::decode(bytes.clone()) {
            let mut current = node;

            // TODO: handle if `path` is now empty
            for part in path {
                match current.typ() {
                    DataType::Directory => {
                        let next_link = current
                            .get_link_by_name(&part)
                            .await?
                            .ok_or_else(|| anyhow!("link {} not found", part))?;
                        let next_bytes = self.load_cid(&next_link.cid).await?;
                        let next_node = UnixfsNode::decode(next_bytes)?;

                        current = next_node;
                    }
                    _ => todo!(),
                }
            }

            Ok(Out::Unixfs(current))
        } else {
            self.resolve_dag_pb(cid, bytes, path).await
        }
    }

    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_dag_pb(&self, cid: Cid, bytes: Bytes, path: Vec<String>) -> Result<Out> {
        let ipld: libipld::Ipld = libipld::IpldCodec::DagPb
            .decode(&bytes)
            .map_err(|e| anyhow!("invalid dag cbor: {:?}", e))?;

        let out = self
            .resolve_ipld(cid, libipld::IpldCodec::DagPb, ipld, path)
            .await?;
        Ok(Out::DagPb(out))
    }

    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_dag_cbor(&self, cid: Cid, bytes: Bytes, path: Vec<String>) -> Result<Out> {
        let ipld: libipld::Ipld = libipld::IpldCodec::DagCbor
            .decode(&bytes)
            .map_err(|e| anyhow!("invalid dag cbor: {:?}", e))?;

        let out = self
            .resolve_ipld(cid, libipld::IpldCodec::DagCbor, ipld, path)
            .await?;
        Ok(Out::DagCbor(out))
    }

    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_dag_json(&self, cid: Cid, bytes: Bytes, path: Vec<String>) -> Result<Out> {
        let ipld: libipld::Ipld = libipld::IpldCodec::DagJson
            .decode(&bytes)
            .map_err(|e| anyhow!("invalid dag json: {:?}", e))?;

        let out = self
            .resolve_ipld(cid, libipld::IpldCodec::DagJson, ipld, path)
            .await?;
        Ok(Out::DagJson(out))
    }

    #[tracing::instrument(skip(self, bytes))]
    async fn resolve_raw(&self, cid: Cid, bytes: Bytes, path: Vec<String>) -> Result<Out> {
        let ipld: libipld::Ipld = libipld::IpldCodec::Raw
            .decode(&bytes)
            .map_err(|e| anyhow!("invalid raw: {:?}", e))?;

        let out = self
            .resolve_ipld(cid, libipld::IpldCodec::Raw, ipld, path)
            .await?;
        Ok(Out::Raw(out))
    }

    #[tracing::instrument(skip(self))]
    async fn resolve_ipld(
        &self,
        _cid: Cid,
        codec: libipld::IpldCodec,
        root: Ipld,
        path: Vec<String>,
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
                part.into()
            };

            current = current.get(index)?;
        }

        // TODO: can we avoid this clone?

        Ok(current.clone())
    }

    #[tracing::instrument(skip(self))]
    async fn resolve_root(&self, typ: PathType, root: &CidOrDomain) -> Result<(Cid, Bytes)> {
        match typ {
            PathType::Ipfs => match root {
                CidOrDomain::Cid(ref c) => Ok((*c, self.load_cid(c).await?)),
                CidOrDomain::Domain(_) => bail!("invalid domain encountered"),
            },
            PathType::Ipns => match root {
                CidOrDomain::Cid(ref c) => Ok((*c, self.load_cid(c).await?)),
                CidOrDomain::Domain(ref domain) => {
                    let c = self.resolve_dnslink(domain).await?;
                    Ok((c, self.load_cid(&c).await?))
                }
            },
        }
    }

    /// Loads the actual content of a given cid.
    #[tracing::instrument(skip(self))]
    async fn load_cid(&self, cid: &Cid) -> Result<Bytes> {
        trace!("loading cid");
        // TODO: better strategy

        let cid = *cid;
        match self.rpc.store.get(cid).await {
            Ok(Some(data)) => {
                trace!("retrieved from store");
                return Ok(data);
            }
            Ok(None) => {}
            Err(err) => {
                warn!("failed to fetch data from store {}: {:?}", cid, err);
            }
        }

        let providers = self.rpc.p2p.fetch_providers(&cid).await?;
        let bytes = self.rpc.p2p.fetch_bitswap(cid, Some(providers)).await?;

        // TODO: is this the right place?
        // verify cid
        match Code::try_from(cid.hash().code()) {
            Ok(code) => {
                let bytes = bytes.clone();
                tokio::task::spawn_blocking(move || {
                    let calculated_hash = code.digest(&bytes);
                    if &calculated_hash != cid.hash() {
                        bail!(
                            "invalid data returned {:?} != {:?}",
                            calculated_hash,
                            cid.hash()
                        );
                    }
                    Ok(())
                })
                .await??;
            }
            Err(_) => {
                warn!(
                    "unable to verify hash, unknown hash function {} for {}",
                    cid.hash().code(),
                    cid
                );
            }
        }

        // trigger storage in the background
        let cloned = bytes.clone();
        let rpc = self.rpc.clone();
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

    /// Resolves a dnslink at the given domain.
    #[tracing::instrument(skip(self))]
    async fn resolve_dnslink(&self, _domain: &str) -> Result<Cid> {
        todo!()
    }
}

fn parse_links(cid: &Cid, bytes: &[u8]) -> Result<Vec<Cid>> {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use cid::multihash::{Code, MultihashDigest};
    use iroh_rpc_client::RpcClientConfig;
    use libipld::{codec::Encode, Ipld, IpldCodec};

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

            let client = Client::new(&RpcClientConfig::default()).await.unwrap();
            let resolver = Resolver::new(client);

            {
                let new_ipld = resolver
                    .resolve_ipld(c, codec, ipld.clone(), vec!["name".to_string()])
                    .await
                    .unwrap();

                assert_eq!(new_ipld, Ipld::String("Foo".to_string()));
            }
            {
                let new_ipld = resolver
                    .resolve_ipld(
                        c,
                        codec,
                        ipld.clone(),
                        vec!["details".to_string(), "0".to_string()],
                    )
                    .await
                    .unwrap();
                assert_eq!(new_ipld, Ipld::Integer(1));
            }
        }
    }
}
