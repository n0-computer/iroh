use core::hash;
use std::process::Output;

use anyhow::Context;
use futures_util::Future;
use iroh::node::{Builder, Node};
use iroh_base::ticket::BlobTicket;
use tokio::task::JoinSet;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn in_rt(x: impl Future<Output = anyhow::Result<()>>) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(x)
}

#[test]
fn test_sync_1to10() -> anyhow::Result<()> {
    let temp_dir = tempfile::tempdir().context("tempdir")?;
    let (s, r) = std::sync::mpsc::channel();
    let temp_path = temp_dir.path().to_path_buf();
    std::thread::spawn(|| {
        in_rt(async move {
            let sender = Builder::default()
                .persist(temp_path.join("sender"))
                .await?
                .spawn()
                .await?;
            let bytes = vec![0u8; 1024 * 1024 * 1024];
            let addr = sender.my_addr().await?;
            let res: iroh::client::blobs::AddOutcome =
                sender.client().blobs().add_bytes(bytes).await?;
            s.send((addr, res.hash)).unwrap();
            futures_lite::future::pending::<()>().await;
            Ok(())
        })
        .unwrap();
    });
    let (addr, hash) = r.recv().unwrap();
    eprintln!("sender spawned");
    let mut receivers = Vec::new();
    for i in 0..10 {
        let addr = addr.clone();
        let temp_path = temp_dir.path().to_path_buf();
        receivers.push(std::thread::spawn(move || {
            in_rt(async move {
                eprintln!("spawning receiver {}", i);
                let receiver = Builder::default()
                    .persist(temp_path.join(format!("receiver-{}", i)))
                    .await?
                    .spawn()
                    .await?;
                eprintln!("spawned receiver {}", i);
                eprintln!("downloading {}", i);
                let _oc = receiver
                    .client()
                    .blobs()
                    .download(hash, addr)
                    .await?
                    .await?;
                eprintln!("exporting {}", i);
                let mut reader = receiver.client().blobs().read(hash).await?;
                tokio::io::copy(&mut reader, &mut tokio::io::stdout()).await?;
                eprintln!("done {}", i);
                receiver.shutdown().await?;
                eprintln!("shutdown {}", i);
                Ok(())
            })
            .unwrap();
        }));
    }
    for x in receivers {
        x.join().unwrap();
    }
    Ok(())
}

fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}
