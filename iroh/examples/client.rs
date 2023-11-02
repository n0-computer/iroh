//! This example shows the shortest path to working with documents in iroh. This example creates a
//! document and sets an entry with key: "hello", value: "world". The document is completely local.
//!
//! The iroh node that creates the document is backed by an in-memory database and a random peer ID
//!
//! run this example from the project root:
//!     $ cargo run --example client
use indicatif::HumanBytes;
use iroh::node::Node;
use iroh_bytes::util::runtime;
use iroh_sync::{
    store::{Query},
    Entry,
};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rt = runtime::Handle::from_current(1)?;
    let db = iroh_bytes::store::mem::Store::new(rt.clone());
    let store = iroh_sync::store::memory::Store::default();
    let node = Node::builder(db.clone(), store)
        .runtime(&rt)
        .spawn()
        .await?;
    let client = node.client();
    let doc = client.docs.create().await?;
    let author = client.authors.create().await?;
    let key = b"hello".to_vec();
    let value = b"world".to_vec();
    doc.set_bytes(author, key.clone(), value).await?;
    let mut stream = doc.get_many(Query::all()).await?;
    while let Some(entry) = stream.try_next().await? {
        println!("entry {}", fmt_entry(&entry));
        let content = doc.read_to_bytes(&entry).await?;
        println!("  content {}", String::from_utf8(content.to_vec())?)
    }

    Ok(())
}

fn fmt_entry(entry: &Entry) -> String {
    let id = entry.id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_hash(id.author());
    let hash = entry.content_hash();
    let hash = fmt_hash(hash.as_bytes());
    let len = HumanBytes(entry.content_len());
    format!("@{author}: {key} = {hash} ({len})",)
}

fn fmt_hash(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&hash.as_ref()[..5]);
    text.make_ascii_lowercase();
    format!("{}…", &text)
}
