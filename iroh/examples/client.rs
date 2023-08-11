use std::time::Duration;

use indicatif::HumanBytes;
use iroh::node::Node;
use iroh_bytes::util::runtime;
use iroh_sync::{
    store::{GetFilter, KeyFilter},
    sync::SignedEntry,
};
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
    for i in 0..5 {
        let key = format!("hello {i}").as_bytes().to_vec();
        let value = format!("world {i}").as_bytes().to_vec();
        doc.set_bytes(author, key.clone(), value).await?;
    }
    let mut stream = doc
        .get(GetFilter {
            latest: true,
            key: KeyFilter::All,
            author: None,
        })
        .await?;
    while let Some(entry) = stream.try_next().await? {
        println!("entry {}", fmt_entry(&entry));
        let content = doc.get_content_bytes(&entry).await?;
        println!("  content {}", String::from_utf8(content.to_vec())?)
    }

    let ticket = doc.share(iroh::rpc_protocol::ShareMode::Write).await?;
    println!("ticket: {}", ticket);

    let mut counter = 0;
    loop {
        counter += 1;
        for i in 0..5 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let key = format!("hello {i}");
            println!("updating {key}");
            let key = key.as_bytes().to_vec();
            let value = format!("world {counter}").as_bytes().to_vec();
            doc.set_bytes(author, key.clone(), value).await?;
        }
    }
    Ok(())
}

fn fmt_entry(entry: &SignedEntry) -> String {
    let id = entry.entry().id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_hash(id.author().as_bytes());
    let hash = entry.entry().record().content_hash();
    let hash = fmt_hash(hash.as_bytes());
    let len = HumanBytes(entry.entry().record().content_len());
    format!("@{author}: {key} = {hash} ({len})",)
}

fn fmt_hash(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&hash.as_ref()[..5]);
    text.make_ascii_lowercase();
    format!("{}…", &text)
}
