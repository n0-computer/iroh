//! Simple example of a mini blockchain on iroh

use anyhow::Result;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use iroh::{blobs::Hash, client::MemIroh};

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
struct Block {
    /// Block number.
    id: u64,
    /// Link to the previous block.
    parent: Hash,
    /// Actual block data
    data: BlockData,
}

impl Block {
    async fn store(&self, node: &MemIroh) -> Result<Hash> {
        let encoded_block_data = postcard::to_stdvec(&self.data)?;
        let res = node.blobs().add_bytes(encoded_block_data).await?;
        let block_data_hash = res.hash;
        let block_header = BlockHeader {
            id: self.id,
            parent: self.parent,
            data: block_data_hash,
        };

        let encoded_block_header = postcard::to_stdvec(&block_header)?;
        let res = node.blobs().add_bytes(encoded_block_header).await?;
        Ok(res.hash)
    }

    async fn load(hash: Hash, node: &MemIroh) -> Result<Self> {
        let block_header_raw = node.blobs().read_to_bytes(hash).await?;
        let block_header: BlockHeader = postcard::from_bytes(&block_header_raw)?;
        let block_data_raw = node.blobs().read_to_bytes(block_header.data).await?;
        let block_data: BlockData = postcard::from_bytes(&block_data_raw)?;

        Ok(Block {
            id: block_header.id,
            parent: block_header.parent,
            data: block_data,
        })
    }

    async fn add_link(&mut self, node: &MemIroh, name: &str, data: impl Into<Bytes>) -> Result<()> {
        let res = node.blobs().add_bytes(data).await?;
        self.data.links.push((name.to_string(), res.hash));
        Ok(())
    }

    async fn load_links(&self, node: &MemIroh) -> Result<Vec<(String, Bytes)>> {
        let mut out = Vec::with_capacity(self.data.links.len());

        for (name, hash) in &self.data.links {
            let data = node.blobs().read_to_bytes(*hash).await?;
            out.push((name.clone(), data));
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
struct BlockHeader {
    /// Block number.
    id: u64,
    /// Link to the previous block.
    parent: Hash,
    /// Link to the block data
    data: Hash,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
struct BlockData {
    /// Some block data.
    data: String,
    /// Some links to things.
    links: Vec<(String, Hash)>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // create a new node
    let node = iroh::node::Node::memory().spawn().await?;

    // make a tiny "block chain"

    // genesis
    let block_0_hash = {
        let mut block_0 = Block {
            id: 0,
            parent: Hash::EMPTY, // no parent
            data: BlockData {
                data: "genesis".to_string(),
                links: Vec::new(),
            },
        };

        for i in 0..5 {
            block_0
                .add_link(&node, &format!("{i}-link"), format!("hello world {i}"))
                .await?;
        }

        block_0.store(&node).await?
    };

    println!("stored genesis block {}", block_0_hash);

    // refetch block + data
    let block_0 = Block::load(block_0_hash, &node).await?;
    println!("got block: {:#?}", block_0);

    let links = block_0.load_links(&node).await?;
    println!("got links:");
    for (name, data) in links {
        println!("- {}: '{}'", name, std::str::from_utf8(&data)?);
    }

    Ok(())
}
