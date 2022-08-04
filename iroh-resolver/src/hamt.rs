use anyhow::{bail, ensure, Result};
use async_recursion::async_recursion;
use once_cell::sync::OnceCell;

use crate::{
    resolver::{ContentLoader, OutContent, Path, Resolver},
    unixfs::{self, HamtHashFunction, Link, Links, PbLinks, UnixfsNode},
};

use self::{bitfield::Bitfield, hash_bits::HashBits};

#[allow(dead_code)]
mod bitfield;
mod hash_bits;

const HASH_BIT_LENGTH: usize = 8;

/// Maximum depth, this is the length of a hashed key.
const MAX_DEPTH: usize = HASH_BIT_LENGTH;

const DEFAULT_FANOUT: u32 = 256;

#[derive(Debug)]
pub struct Hamt {
    root: Node,
}

#[derive(Debug)]
struct Node {
    bitfield: Bitfield,
    bit_width: u32,
    padding_len: usize,
    pointers: Vec<NodeLink>,
}

#[derive(Debug)]
struct NodeLink {
    link: Link,
    cache: OnceCell<Box<InnerNode>>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum InnerNode {
    Node(Node),
    Leaf { link: Link, value: UnixfsNode },
}

impl Hamt {
    pub fn from_node(node: &unixfs::Node) -> Result<Self> {
        let root = Node::from_node(node)?;
        Ok(Self { root })
    }

    pub async fn get<C: ContentLoader>(
        &self,
        loader: &Resolver<C>,
        key: &[u8],
    ) -> Result<Option<(&Link, &UnixfsNode)>> {
        self.root.get(loader, key).await
    }
}

impl InnerNode {
    pub async fn load_from_link<C: ContentLoader>(
        link: &Link,
        loader: &Resolver<C>,
    ) -> Result<Self> {
        let path = Path::from_cid(link.cid);
        let out = loader.resolve(path).await?;
        match out.content {
            OutContent::Unixfs(node) => match node {
                UnixfsNode::HamtShard(ref shard) => {
                    let node = Node::from_node(shard)?;
                    Ok(InnerNode::Node(node))
                }
                UnixfsNode::File(_) => Ok(InnerNode::Leaf {
                    link: link.clone(),
                    value: node,
                }),
                _ => bail!("unexpected unixfs node: {:?}", node.typ()),
            },
            _ => bail!("unexpected node: {:?}", out.content.typ()),
        }
    }
}

impl Node {
    pub fn from_node(node: &unixfs::Node) -> Result<Self> {
        ensure!(
            node.hash_type() == Some(HamtHashFunction::Murmur3),
            "hamt: only murmur3 is supported"
        );
        let fanout = node.fanout().unwrap_or(DEFAULT_FANOUT);
        ensure!(fanout > 0, "fanout must be non zero");

        let data = node.data().as_ref().unwrap().clone();
        let bitfield = Bitfield::from_slice(&data[..])?;

        let links = Links::HamtShard(PbLinks::new(&node.outer));
        let pointers = links
            .map(|l| {
                Ok(NodeLink {
                    link: l?.to_owned(),
                    cache: Default::default(),
                })
            })
            .collect::<Result<_>>()?;

        let bit_width = log2(fanout);
        let padding_len = format!("{:X}", fanout - 1).len();

        Ok(Node {
            bitfield,
            pointers,
            bit_width,
            padding_len,
        })
    }

    pub async fn get<C: ContentLoader>(
        &self,
        loader: &Resolver<C>,
        key: &[u8],
    ) -> Result<Option<(&Link, &UnixfsNode)>> {
        let hashed_key = hash_key(key);
        let res = self
            .get_value(loader, &mut HashBits::new(&hashed_key), key, 0)
            .await?;
        Ok(res)
    }

    #[async_recursion]
    pub async fn get_value<C: ContentLoader>(
        &self,
        loader: &Resolver<C>,
        hashed_key: &mut HashBits<'_, HASH_BIT_LENGTH>,
        key: &[u8],
        depth: usize,
    ) -> Result<Option<(&Link, &UnixfsNode)>> {
        ensure!(depth < MAX_DEPTH, "max depth reached");
        let idx = hashed_key.next(self.bit_width)?;
        if !self.bitfield.test_bit(idx) {
            return Ok(None);
        }

        let cindex = self.index_for_bit_pos(idx);
        let child = self.get_child(cindex);
        let cached_node = if let Some(cached_node) = child.cache.get() {
            cached_node
        } else {
            match InnerNode::load_from_link(&child.link, loader).await {
                Ok(node) => child.cache.get_or_init(|| Box::new(node)),
                Err(_) => return Ok(None),
            }
        };

        let cached_node: &InnerNode = &*cached_node;
        match cached_node {
            InnerNode::Node(node) => node.get_value(loader, hashed_key, key, depth + 1).await,
            InnerNode::Leaf { link, value } => {
                let name = link
                    .name
                    .as_ref()
                    .map(|s| &s.as_bytes()[self.padding_len..])
                    .unwrap_or_default();
                if key == name {
                    Ok(Some((link, value)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn index_for_bit_pos(&self, bp: u32) -> usize {
        let mask = Bitfield::zero().set_bits_le(bp);
        assert_eq!(mask.count_ones(), bp as usize);
        mask.and(&self.bitfield).count_ones()
    }

    fn get_child(&self, i: usize) -> &NodeLink {
        &self.pointers[i]
    }
}

/// Hashes with murmur3 x64 and returns the first 64 bits.
/// This matches what go-unixfs uses.
fn hash_key(key: &[u8]) -> [u8; HASH_BIT_LENGTH] {
    let full = fastmurmur3::hash(key);
    // [h1, h2]
    let bytes = full.to_ne_bytes();
    // get h1
    let h1 = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
    // big endian, because go
    h1.to_be_bytes()
}

fn log2(x: u32) -> u32 {
    assert!(x > 0);
    u32::BITS as u32 - x.leading_zeros() - 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_key() {
        assert_eq!(
            hash_key("1.txt".as_bytes()),
            [7, 193, 130, 130, 92, 180, 71, 225]
        );
    }
}
