use anyhow::{ensure, Result};
use futures::{stream::BoxStream, Stream, StreamExt};
use once_cell::sync::OnceCell;

use crate::{
    content_loader::{ContentLoader, LoaderContext},
    types::PbLinks,
    unixfs::{self, HamtHashFunction, UnixfsNode},
    Link, Links,
};
use async_recursion::async_recursion;

use self::{bitfield::Bitfield, hash_bits::HashBits};

#[allow(dead_code)]
pub(crate) mod bitfield;
mod hash_bits;

const HASH_BIT_LENGTH: usize = 8;

/// Maximum depth, this is the length of a hashed key.
const MAX_DEPTH: usize = HASH_BIT_LENGTH;

const DEFAULT_FANOUT: u32 = 256;

#[derive(Debug, PartialEq, Clone)]
pub struct Hamt {
    root: Node,
}

#[derive(Debug, PartialEq, Clone)]
struct Node {
    bitfield: Bitfield,
    bit_width: u32,
    padding_len: usize,
    pointers: Vec<NodeLink>,
}

#[derive(Debug, PartialEq, Clone)]
struct NodeLink {
    link: Link,
    cache: OnceCell<Box<InnerNode>>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone)]
enum InnerNode {
    Node { node: Node, value: UnixfsNode },
    Leaf { link: Link, value: UnixfsNode },
}

impl Hamt {
    pub fn from_node(node: &unixfs::Node) -> Result<Self> {
        let root = Node::from_node(node)?;
        Ok(Self { root })
    }

    pub async fn get<C: ContentLoader>(
        &self,
        ctx: LoaderContext,
        loader: C,
        key: &[u8],
    ) -> Result<Option<(&Link, &UnixfsNode)>> {
        self.root.get(ctx, loader, key).await
    }

    pub fn padding_len(&self) -> usize {
        self.root.padding_len
    }

    pub fn calculate_padding_len(node: &unixfs::Node) -> usize {
        let fanout = node.fanout().unwrap_or(DEFAULT_FANOUT);
        // TODO: avoid allocation
        let padding = format!("{:X}", fanout - 1);
        padding.len()
    }

    pub fn children<C: ContentLoader>(
        &self,
        ctx: LoaderContext,
        loader: C,
    ) -> impl Stream<Item = Result<Link>> + '_ {
        self.root.children(ctx, loader)
    }
}

impl InnerNode {
    pub async fn load_from_link<C: ContentLoader>(
        ctx: LoaderContext,
        link: &Link,
        loader: C,
    ) -> Result<Self> {
        let cid = link.cid;
        let loaded_cid = loader.load_cid(&cid, &ctx).await?;
        let node = UnixfsNode::decode(&cid, loaded_cid.data)?;

        match node {
            UnixfsNode::HamtShard(_, ref hamt) => Ok(InnerNode::Node {
                node: hamt.root.clone(),
                value: node,
            }),
            UnixfsNode::RawNode(_)
            | UnixfsNode::File(_)
            | UnixfsNode::Directory(_)
            | UnixfsNode::Raw(_)
            | UnixfsNode::Symlink(_) => Ok(InnerNode::Leaf {
                link: link.clone(),
                value: node,
            }),
        }
    }

    fn children<C: ContentLoader>(
        &self,
        ctx: LoaderContext,
        loader: C,
    ) -> impl Stream<Item = Result<Link>> + '_ {
        async_stream::try_stream! {
            match self {
                InnerNode::Node { node, .. } => {
                    let mut children = node.children(ctx, loader);
                    while let Some(link) = children.next().await {
                        let link = link?;
                        yield link;
                    }

                },
                InnerNode::Leaf { value, .. } => match value {
                    UnixfsNode::Directory(_) => {
                        for link in value.links() {
                            let link = link?;
                            yield link.to_owned();
                        }
                    }
                    UnixfsNode::HamtShard(_, hamt) => {
                        let mut children = hamt.children(ctx, loader);
                        while let Some(link) = children.next().await {
                            let link = link?;
                            yield link;
                        }
                    }
                    _ => {}
                }
            }
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
                let l = l?;
                Ok(NodeLink {
                    link: l.to_owned(),
                    cache: Default::default(),
                })
            })
            .collect::<Result<_>>()?;

        let bit_width = log2(fanout);
        let padding = format!("{:X}", fanout - 1);
        let padding_len = padding.len();

        Ok(Node {
            bitfield,
            pointers,
            bit_width,
            padding_len,
        })
    }

    pub async fn get<C: ContentLoader>(
        &self,
        ctx: LoaderContext,
        loader: C,
        key: &[u8],
    ) -> Result<Option<(&Link, &UnixfsNode)>> {
        let hashed_key = hash_key(key);
        let res = self
            .get_value(ctx, loader, &mut HashBits::new(&hashed_key), key, 0)
            .await?;

        Ok(res)
    }

    #[async_recursion]
    pub async fn get_value<C: ContentLoader>(
        &self,
        ctx: LoaderContext,
        loader: C,
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
        let cached_node = self.load_child(ctx.clone(), loader.clone(), child).await?;
        match cached_node {
            InnerNode::Node { node, value } => {
                let name = child
                    .link
                    .name
                    .as_ref()
                    .map(|s| &s.as_bytes()[self.padding_len..])
                    .unwrap_or_default();

                if key == name {
                    Ok(Some((&child.link, value)))
                } else {
                    node.get_value(ctx, loader, hashed_key, key, depth + 1)
                        .await
                }
            }
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

    async fn load_child<'a, C: ContentLoader>(
        &self,
        ctx: LoaderContext,
        loader: C,
        child: &'a NodeLink,
    ) -> Result<&'a InnerNode> {
        if let Some(cached_node) = child.cache.get() {
            Ok(cached_node)
        } else {
            let node = InnerNode::load_from_link(ctx, &child.link, loader).await?;
            Ok(child.cache.get_or_init(|| Box::new(node)))
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

    fn children<C: ContentLoader>(&self, ctx: LoaderContext, loader: C) -> BoxStream<Result<Link>> {
        async_stream::try_stream! {
            let padding_len = self.padding_len;
            for pointer in &self.pointers {
                if let Some(ref name) = pointer.link.name {
                    if name.len() > padding_len {
                        yield Link {
                            cid: pointer.link.cid,
                            name: pointer.link.name.as_ref().map(|n| {
                                std::str::from_utf8(&n.as_bytes()[padding_len..]).unwrap().to_string()
                            }),
                            tsize: pointer.link.tsize,
                        };
                    } else {
                        // recurse
                        let child = self.load_child(ctx.clone(), loader.clone(), pointer).await?;
                        let children = child.children(ctx.clone(), loader.clone());
                        tokio::pin!(children);
                        while let Some(link) = children.next().await {
                            let link = link?;
                            yield link;
                        }
                    }
                }
            }
        }
        .boxed()
    }
}

/// Hashes with murmur3 x64 and returns the first 64 bits.
/// This matches what go-unixfs uses.
pub(crate) fn hash_key(key: &[u8]) -> [u8; HASH_BIT_LENGTH] {
    let full = fastmurmur3::hash(key);
    // [h1, h2]
    let bytes = full.to_ne_bytes();
    // get h1
    let h1 = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
    // big endian, because go
    h1.to_be_bytes()
}

pub(crate) fn bits(hash: &[u8; 8], pos: u32, len: u32) -> anyhow::Result<u32> {
    let mut hash = HashBits::new_at_index(hash, pos);
    hash.next(len)
}

fn log2(x: u32) -> u32 {
    assert!(x > 0);
    u32::BITS - x.leading_zeros() - 1
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
