use std::collections::VecDeque;

use anyhow::Result;
use async_stream::try_stream;
use bytes::{Bytes, BytesMut};
use cid::Cid;
use futures::{Stream, StreamExt};

use crate::unixfs::{dag_pb, unixfs_pb, DataType, Node, UnixfsNode};
use crate::unixfs_builder::encode_unixfs_pb;

/// Default degree number for balanced tree, taken from unixfs specs
/// https://github.com/ipfs/specs/blob/main/UNIXFS.md#layout
pub const DEFAULT_DEGREE: usize = 174;

#[derive(Debug, PartialEq, Eq)]
pub enum TreeBuilder {
    /// TreeBuilder that builds a "balanced tree" with a max degree size of
    /// degree
    Balanced { degree: usize },
}

impl TreeBuilder {
    pub fn balanced_tree() -> Self {
        Self::balanced_tree_with_degree(DEFAULT_DEGREE)
    }

    pub fn balanced_tree_with_degree(degree: usize) -> Self {
        TreeBuilder::Balanced { degree }
    }

    pub fn stream_tree(
        &self,
        chunks: impl Stream<Item = std::io::Result<BytesMut>>,
    ) -> impl Stream<Item = Result<(Cid, Bytes)>> {
        match self {
            TreeBuilder::Balanced { degree } => stream_balanced_tree(chunks, *degree),
        }
    }
}

fn stream_balanced_tree(
    in_stream: impl Stream<Item = std::io::Result<BytesMut>>,
    degree: usize,
) -> impl Stream<Item = Result<(Cid, Bytes)>> {
    try_stream! {
        // degree = 8
        // VecDeque![ vec![] ]
        // ..
        // VecDeque![ vec![0, 1, 2, 3, 4, 5, 6, 7] ]
        // VecDeque![ vec![8], vec![p0] ]

        // ..

        // VecDeque![ vec![0, 1, 2, 3, 4, 5, 6, 7] vec![p0] ]
        // VecDeque![ vec![], vec![p0, p1]]

        // ..

        // VecDeque![ vec![0, 1, 2, 3, 4, 5, 6, 7] vec![p0, p1, p2, p3, p4, p5, p6, p7], ]
        // VecDeque![ vec![], vec![p0, p1, p2, p3, p4, p5, p6, p7], vec![] ]
        // VecDeque![ vec![8], vec![p8], vec![pp0] ]
        //
        // A vecdeque of vecs, the first vec representing the lowest layer of stem nodes
        // and the last vec representing the root node
        // Since we emit leaf and stem nodes as we go, we only need to keep track of the
        // most "recent" branch, storing the links to that node's children & yielding them
        // when each node reaches `degree` number of links
        let mut tree: VecDeque<Vec<(Cid, u64)>> = VecDeque::new();
        tree.push_back(Vec::with_capacity(degree));

        tokio::pin!(in_stream);

        while let Some(chunk) = in_stream.next().await {
            let chunk = chunk?;
            let chunk = chunk.freeze();
            let tree_len = tree.len();

            // check if the leaf node of the tree is full
            if tree[0].len() == degree {
                // if so, iterate through nodes
                for i in 0..tree_len {
                    // if we encounter any nodes that are not full, break
                    if tree[i].len() < degree {
                        break;
                    }

                    // in this case we have a full set of links & we are
                    // at the top of the tree. Time to make a new layer.
                    if i == tree_len - 1 {
                        tree.push_back(Vec::with_capacity(degree));
                    }

                    // create node, keeping the cid
                    let links = std::mem::replace(&mut tree[i], Vec::with_capacity(degree));
                    let (cid, bytes, len) = TreeNode::Stem(links).encode()?;
                    yield (cid, bytes);

                    // add cid to parent node
                    tree[i+1].push((cid, len));
                }
                // at this point the tree will be able to recieve new links
                // without "overflowing", aka the leaf node and stem nodes
                // have fewer than `degree` number of links
            }

            // now that we know the tree is in a "healthy" state to
            // recieve more links, add the link to the tree
            let (cid, bytes, len) = TreeNode::Leaf(chunk).encode()?;
            tree[0].push((cid, len));
            yield (cid, bytes);
            // at this point, the leaf node may have `degree` number of
            // links, but no other stem node will
        }

        // our stream had 1 chunk that we have already yielded
        if tree.len() == 1 && tree[0].len() == 1 {
            return
        }

        // clean up, aka yield the rest of the stem nodes
        // since all the stem nodes are able to recieve links
        // we don't have to worry about "overflow"
        while let Some(links) = tree.pop_front() {
            let (cid, bytes, len) = TreeNode::Stem(links).encode()?;
            yield (cid, bytes);

            if let Some(front) = tree.front_mut() {
                front.push((cid, len));
            } else {
                // final root, nothing to do
            }
        }
    }
}

fn create_unixfs_node_from_links(links: Vec<(Cid, u64)>) -> Result<UnixfsNode> {
    let links = links
        .into_iter()
        .map(|(cid, len)| dag_pb::PbLink {
            hash: Some(cid.to_bytes()),
            /// ALL "stem" nodes have `name: None`.
            /// In kubo, nodes that have links to `leaf` nodes have `name: Some("".to_string())`
            name: None,
            /// tsize has no strict definition
            /// Iroh's definiton of `tsize` is "the cumulative size of the encoded tree
            /// pointed to by this link", so not just the size of the raw content, but including
            /// all encoded dag nodes as well.
            /// In the `go-merkledag` package, the `merkledag.proto` file, states that tsize
            /// is the "cumulative size of the target object"
            /// (https://github.com/ipfs/go-merkledag/blob/8335efd4765ed5a512baa7e522c3552d067cf966/pb/merkledag.proto#L29)
            tsize: Some(len as u64),
        })
        .collect();

    // PBNode.Data
    let inner = unixfs_pb::Data {
        r#type: DataType::File as i32,
        ..Default::default()
    };

    // create PBNode
    let outer = encode_unixfs_pb(&inner, links)?;

    // create UnixfsNode
    Ok(UnixfsNode::File(Node { inner, outer }))
}

// Leaf and Stem nodes are the two types of nodes that can exist in the tree
// Leaf nodes encode to `UnixfsNode::Raw`
// Stem nodes encode to `UnixfsNode::File`
enum TreeNode {
    Leaf(Bytes),
    Stem(Vec<(Cid, u64)>),
}

impl TreeNode {
    fn encode(self) -> Result<(Cid, Bytes, u64)> {
        match self {
            TreeNode::Leaf(bytes) => {
                let node = UnixfsNode::Raw(bytes);
                let (cid, bytes) = node.encode()?;
                let len = bytes.len();
                Ok((cid, bytes, len as u64))
            }
            TreeNode::Stem(links) => {
                let mut cumulative_len: u64 = links.iter().map(|(_, len)| len).sum();
                let node = create_unixfs_node_from_links(links)?;
                let (cid, bytes) = node.encode()?;
                cumulative_len += bytes.len() as u64;
                Ok((cid, bytes, cumulative_len))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    fn test_chunk_stream(num_chunks: usize) -> impl Stream<Item = std::io::Result<BytesMut>> {
        futures::stream::iter((0..num_chunks).map(|n| Ok(BytesMut::from(&n.to_be_bytes()[..]))))
    }

    async fn build_expect_tree(num_chunks: usize, degree: usize) -> Vec<Vec<(Cid, Bytes)>> {
        let chunks = test_chunk_stream(num_chunks);
        tokio::pin!(chunks);
        let mut tree = vec![vec![]];
        let mut links = vec![vec![]];

        if num_chunks / degree == 0 {
            let chunk = chunks.next().await.unwrap().unwrap();
            let leaf = TreeNode::Leaf(chunk.freeze());
            let (cid, bytes, _) = leaf.encode().unwrap();
            tree[0].push((cid, bytes));
            return tree;
        }

        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.unwrap();
            let leaf = TreeNode::Leaf(chunk.freeze());
            let (cid, bytes, len) = leaf.encode().unwrap();
            tree[0].push((cid, bytes));
            links[0].push((cid, len));
        }

        while tree.last().unwrap().len() > 1 {
            let prev_layer = links.last().unwrap();
            let count = prev_layer.len() / degree;
            let mut tree_layer = Vec::with_capacity(count);
            let mut links_layer = Vec::with_capacity(count);
            for links in prev_layer.chunks(degree) {
                let stem = TreeNode::Stem(links.to_vec());
                let (cid, bytes, len) = stem.encode().unwrap();
                tree_layer.push((cid, bytes));
                links_layer.push((cid, len));
            }
            tree.push(tree_layer);
            links.push(links_layer);
        }
        tree
    }

    async fn build_expect_vec_from_tree(
        tree: Vec<Vec<(Cid, Bytes)>>,
        num_chunks: usize,
        degree: usize,
    ) -> Vec<(Cid, Bytes)> {
        let mut out = vec![];

        if num_chunks == 1 {
            out.push(tree[0][0].clone());
            return out;
        }

        let mut counts = vec![0; tree.len()];

        for leaf in tree[0].iter() {
            out.push(leaf.clone());
            counts[0] += 1;
            let mut push = counts[0] % degree == 0;
            for (num_layer, count) in counts.iter_mut().enumerate() {
                if num_layer == 0 {
                    continue;
                }
                if !push {
                    break;
                }
                out.push(tree[num_layer][*count].clone());
                *count += 1;
                if *count % degree != 0 {
                    push = false;
                }
            }
        }

        for (num_layer, count) in counts.into_iter().enumerate() {
            if num_layer == 0 {
                continue;
            }
            let layer = tree[num_layer].clone();
            for node in layer.into_iter().skip(count) {
                out.push(node);
            }
        }

        out
    }

    async fn build_expect(num_chunks: usize, degree: usize) -> Vec<(Cid, Bytes)> {
        let tree = build_expect_tree(num_chunks, degree).await;
        println!("{:?}", tree);
        build_expect_vec_from_tree(tree, num_chunks, degree).await
    }

    fn make_leaf(data: usize) -> (Cid, Bytes, u64) {
        TreeNode::Leaf(BytesMut::from(&data.to_be_bytes()[..]).freeze())
            .encode()
            .unwrap()
    }

    fn make_stem(links: Vec<(Cid, u64)>) -> (Cid, Bytes, u64) {
        TreeNode::Stem(links).encode().unwrap()
    }

    #[tokio::test]
    async fn test_build_expect() {
        // manually build tree made of 7 chunks (11 total nodes)
        let (cid_0, bytes_0, len_0) = make_leaf(0);
        let (cid_1, bytes_1, len_1) = make_leaf(1);
        let (cid_2, bytes_2, len_2) = make_leaf(2);
        let (stem_cid_0, stem_bytes_0, stem_len_0) =
            make_stem(vec![(cid_0, len_0), (cid_1, len_1), (cid_2, len_2)]);
        let (cid_3, bytes_3, len_3) = make_leaf(3);
        let (cid_4, bytes_4, len_4) = make_leaf(4);
        let (cid_5, bytes_5, len_5) = make_leaf(5);
        let (stem_cid_1, stem_bytes_1, stem_len_1) =
            make_stem(vec![(cid_3, len_3), (cid_4, len_4), (cid_5, len_5)]);
        let (cid_6, bytes_6, len_6) = make_leaf(6);
        let (stem_cid_2, stem_bytes_2, stem_len_2) = make_stem(vec![(cid_6, len_6)]);
        let (root_cid, root_bytes, _root_len) = make_stem(vec![
            (stem_cid_0, stem_len_0),
            (stem_cid_1, stem_len_1),
            (stem_cid_2, stem_len_2),
        ]);
        let leaf_0 = (cid_0, bytes_0);
        let leaf_1 = (cid_1, bytes_1);
        let leaf_2 = (cid_2, bytes_2);
        let leaf_3 = (cid_3, bytes_3);
        let leaf_4 = (cid_4, bytes_4);
        let leaf_5 = (cid_5, bytes_5);
        let leaf_6 = (cid_6, bytes_6);

        let stem_0 = (stem_cid_0, stem_bytes_0);
        let stem_1 = (stem_cid_1, stem_bytes_1);
        let stem_2 = (stem_cid_2, stem_bytes_2);

        let root = (root_cid, root_bytes);

        let expect_tree = vec![
            vec![
                leaf_0.clone(),
                leaf_1.clone(),
                leaf_2.clone(),
                leaf_3.clone(),
                leaf_4.clone(),
                leaf_5.clone(),
                leaf_6.clone(),
            ],
            vec![stem_0.clone(), stem_1.clone(), stem_2.clone()],
            vec![root.clone()],
        ];
        let got_tree = build_expect_tree(7, 3).await;
        assert_eq!(expect_tree, got_tree);

        let expect_vec = vec![
            leaf_0, leaf_1, leaf_2, stem_0, leaf_3, leaf_4, leaf_5, stem_1, leaf_6, stem_2, root,
        ];
        let got_vec = build_expect_vec_from_tree(got_tree, 7, 3).await;
        assert_eq!(expect_vec, got_vec);
    }

    async fn ensure_equal(
        expect: Vec<(Cid, Bytes)>,
        got: impl Stream<Item = Result<(Cid, Bytes)>>,
    ) {
        let mut i = 0;
        tokio::pin!(got);
        let mut expected_tsize = 0;
        let mut got_tsize = 0;
        while let Some(node) = got.next().await {
            let (expect_cid, expect_bytes) = expect
                .get(i)
                .expect("too many nodes in balanced tree stream");
            let node = node.expect("unexpected error in balanced tree stream");
            let (got_cid, got_bytes) = node;
            let len = got_bytes.len() as u64;
            println!("node index {}", i);
            assert_eq!(*expect_cid, got_cid);
            assert_eq!(*expect_bytes, got_bytes);
            i += 1;
            if expect.len() == i {
                let node = UnixfsNode::decode(&got_cid, got_bytes).unwrap();
                got_tsize = node.links().map(|l| l.unwrap().tsize.unwrap()).sum();
            } else {
                expected_tsize += len;
            }
        }
        if expect.len() != i {
            panic!(
                "expected at {} nodes of the stream, got {}",
                expect.len(),
                i
            );
        }
        assert_eq!(expected_tsize, got_tsize);
    }

    #[tokio::test]
    async fn balanced_tree_test_leaf() {
        let expect = build_expect(1, 3).await;
        let got = stream_balanced_tree(test_chunk_stream(1), 3);
        tokio::pin!(got);
        ensure_equal(expect, got).await;
    }

    #[tokio::test]
    async fn balanced_tree_test_height_one() {
        let num_chunks = 3;
        let degrees = 3;
        let expect = build_expect(num_chunks, degrees).await;
        let got = stream_balanced_tree(test_chunk_stream(num_chunks), degrees);
        tokio::pin!(got);
        ensure_equal(expect, got).await;
    }

    #[tokio::test]
    async fn balanced_tree_test_height_two_full() {
        let degrees = 3;
        let num_chunks = 9;
        let expect = build_expect(num_chunks, degrees).await;
        let got = stream_balanced_tree(test_chunk_stream(num_chunks), degrees);
        tokio::pin!(got);
        ensure_equal(expect, got).await;
    }

    #[tokio::test]
    async fn balanced_tree_test_height_two_not_full() {
        let degrees = 3;
        let num_chunks = 10;
        let expect = build_expect(num_chunks, degrees).await;
        let got = stream_balanced_tree(test_chunk_stream(num_chunks), degrees);
        tokio::pin!(got);
        ensure_equal(expect, got).await;
    }

    #[tokio::test]
    async fn balanced_tree_test_height_three() {
        let num_chunks = 125;
        let degrees = 5;
        let expect = build_expect(num_chunks, degrees).await;
        let got = stream_balanced_tree(test_chunk_stream(num_chunks), degrees);
        tokio::pin!(got);
        ensure_equal(expect, got).await;
    }

    #[tokio::test]
    async fn balanced_tree_test_large() {
        let num_chunks = 780;
        let degrees = 11;
        let expect = build_expect(num_chunks, degrees).await;
        let got = stream_balanced_tree(test_chunk_stream(num_chunks), degrees);
        tokio::pin!(got);
        ensure_equal(expect, got).await;
    }
}
