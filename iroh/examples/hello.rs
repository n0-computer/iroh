use tracing_subscriber::{prelude::*, EnvFilter};

fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging();
    let mut db = iroh::database::mem::Database::default();
    let rt = iroh::bytes::util::runtime::Handle::from_currrent(1)?;
    let data = [0u8; 1024 * 1024];
    let hash = db.insert(&data);
    let node = iroh::node::Node::builder(db).runtime(&rt).spawn().await?;
    let addrs = node.local_endpoint_addresses().await?;
    println!("Serving {} on {:?}", hash, addrs);
    node.await?;
    Ok(())
}
