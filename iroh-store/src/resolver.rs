use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use cid::Cid;
use libipld::prelude::Codec as _;
use libipld::Ipld;

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

/// Resolves through a given path, returning the [`Cid`] and raw bytes of the final leaf.
pub async fn resolve(path: Path) -> Result<Out> {
    // Resolve the root block.
    let (root_cid, root_bytes) = resolve_root(path.typ, &path.root).await?;

    let codec = Codec::try_from(root_cid.codec()).context("unknown codec")?;
    match codec {
        Codec::DagPb => resolve_dag_pb_or_unixfs(root_cid, root_bytes, path.tail).await,
        Codec::DagCbor => resolve_dag_cbor(root_cid, root_bytes, path.tail).await,
        Codec::DagJson => resolve_dag_json(root_cid, root_bytes, path.tail).await,
        _ => bail!("unsupported codec {:?}", codec),
    }
}

pub enum Out {
    DagPb(Ipld),
    Unixfs(UnixfsNode),
    DagCbor(Ipld),
    DagJson(Ipld),
}

/// Resolves through both DagPb and nested UnixFs DAGs.
async fn resolve_dag_pb_or_unixfs(cid: Cid, bytes: Bytes, path: Vec<String>) -> Result<Out> {
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
                    let next_bytes = load_cid(&next_link.cid).await?;
                    let next_node = UnixfsNode::decode(next_bytes)?;

                    current = next_node;
                }
                _ => todo!(),
            }
        }

        Ok(Out::Unixfs(current))
    } else {
        resolve_dag_pb(cid, bytes, path).await
    }
}

async fn resolve_dag_pb(cid: Cid, bytes: Bytes, path: Vec<String>) -> Result<Out> {
    let ipld: libipld::Ipld = libipld::IpldCodec::DagPb
        .decode(&bytes)
        .map_err(|e| anyhow!("invalid dag cbor: {:?}", e))?;

    let out = resolve_ipld(cid, libipld::IpldCodec::DagPb, ipld, path).await?;
    Ok(Out::DagPb(out))
}

async fn resolve_dag_cbor(cid: Cid, bytes: Bytes, path: Vec<String>) -> Result<Out> {
    let ipld: libipld::Ipld = libipld::IpldCodec::DagCbor
        .decode(&bytes)
        .map_err(|e| anyhow!("invalid dag cbor: {:?}", e))?;

    let out = resolve_ipld(cid, libipld::IpldCodec::DagCbor, ipld, path).await?;
    Ok(Out::DagCbor(out))
}

async fn resolve_dag_json(cid: Cid, bytes: Bytes, path: Vec<String>) -> Result<Out> {
    let ipld: libipld::Ipld = libipld::IpldCodec::DagJson
        .decode(&bytes)
        .map_err(|e| anyhow!("invalid dag json: {:?}", e))?;

    let out = resolve_ipld(cid, libipld::IpldCodec::DagJson, ipld, path).await?;
    Ok(Out::DagJson(out))
}

async fn resolve_ipld(
    cid: Cid,
    codec: libipld::IpldCodec,
    root: Ipld,
    path: Vec<String>,
) -> Result<Ipld> {
    let mut root_cid = cid;
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
            let bytes = load_cid(&c).await?;
            root = codec
                .decode(&bytes)
                .map_err(|e| anyhow!("invalid dag json: {:?}", e))?;
            root_cid = c;
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

async fn resolve_root(typ: PathType, root: &CidOrDomain) -> Result<(Cid, Bytes)> {
    match typ {
        PathType::Ipfs => match root {
            CidOrDomain::Cid(ref c) => Ok((*c, load_cid(c).await?)),
            CidOrDomain::Domain(_) => bail!("invalid domain encountered"),
        },
        PathType::Ipns => match root {
            CidOrDomain::Cid(ref c) => Ok((*c, load_cid(c).await?)),
            CidOrDomain::Domain(ref domain) => {
                let c = resolve_dnslink(domain).await?;
                Ok((c, load_cid(&c).await?))
            }
        },
    }
}

/// Loads the actual content of a given cid.
async fn load_cid(cid: &Cid) -> Result<Bytes> {
    todo!()
}

/// Resolves a dnslink at the given domain.
async fn resolve_dnslink(domain: &str) -> Result<Cid> {
    todo!()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use cid::multihash::{Code, MultihashDigest};
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

        Ipld::Map(map)
    }

    #[tokio::test]
    async fn test_resolve_ipld() {
        for codec in [IpldCodec::DagCbor, IpldCodec::DagJson] {
            let ipld = make_ipld();

            let mut bytes = Vec::new();
            ipld.encode(codec, &mut bytes).unwrap();
            let digest = Code::Blake3_256.digest(&bytes);
            let c = Cid::new_v1(codec.into(), digest);

            {
                let new_ipld = resolve_ipld(c, codec, ipld.clone(), vec!["name".to_string()])
                    .await
                    .unwrap();

                assert_eq!(new_ipld, Ipld::String("Foo".to_string()));
            }
            {
                let new_ipld = resolve_ipld(
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
