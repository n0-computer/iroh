use indicatif::HumanBytes;
use iroh::node::Node;
use iroh_bytes::util::runtime;
use iroh_sync::{store::GetFilter, Entry};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rt = runtime::Handle::from_currrent(1)?;
    let db = iroh::baomap::mem::Store::new(rt.clone());
    let store = iroh_sync::store::memory::Store::default();
    let node = Node::builder(db.clone(), store)
        .runtime(&rt)
        .spawn()
        .await?;
    let client = node.client();
    let doc = client.create_doc().await?;
    let author = client.create_author().await?;
    let key = b"hello".to_vec();
    let value = b"world".to_vec();
    doc.set_bytes(author, key.clone(), value).await?;
    let mut stream = doc.get(GetFilter::latest()).await?;
    while let Some(entry) = stream.try_next().await? {
        println!("entry {}", fmt_entry(&entry));
        let content = doc.get_content_bytes(entry.content_hash()).await?;
        println!("  content {}", String::from_utf8(content.to_vec())?)
    }

    Ok(())
}

fn fmt_entry(entry: &Entry) -> String {
    let id = entry.id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_hash(id.author().as_bytes());
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
