//! This example shows the shortest path to working with documents in iroh. This example creates a
//! document and sets an entry with key: "hello", value: "world". The document is completely local.
//!
//! The iroh node that creates the document is backed by an in-memory database and a random node ID
//!
//! run this example from the project root:
//!     $ cargo run --example client
use indicatif::HumanBytes;
use iroh::{client::Entry, node::Node};
use iroh_base::base32;
use iroh_sync::store::Query;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db = iroh_bytes::store::mem::Store::new();
    let store = iroh_sync::store::memory::Store::default();
    let node = Node::builder(db.clone(), store).spawn().await?;
    let client = node.client();
    let doc = client.docs.create().await?;
    let author = client.authors.create().await?;
    let key = b"hello".to_vec();
    let value = b"world".to_vec();
    doc.set_bytes(author, key.clone(), value).await?;
    let mut stream = doc.get_many(Query::all()).await?;
    while let Some(entry) = stream.try_next().await? {
        println!("entry {}", fmt_entry(&entry));
        let content = entry.content_bytes(&client).await?;
        println!("  content {}", String::from_utf8(content.to_vec())?)
    }

    Ok(())
}

fn fmt_entry(entry: &Entry) -> String {
    let id = entry.id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = base32::fmt_short(id.author());
    let hash = entry.content_hash();
    let hash = base32::fmt_short(hash.as_bytes());
    let len = HumanBytes(entry.content_len());
    format!("@{author}: {key} = {hash} ({len})",)
}
