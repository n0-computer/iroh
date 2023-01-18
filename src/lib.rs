pub mod client;
pub mod protocol;
pub mod server;

mod tls;

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::PathBuf};

    use super::*;
    use anyhow::Result;
    use futures::TryStreamExt;
    use testdir::testdir;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn basics() -> Result<()> {
        let dir: PathBuf = testdir!();
        let path = dir.join("hello_world");
        tokio::fs::write(&path, "hello world!").await?;
        let db = server::create_db(vec![&path]).await?;
        let hash = *db.iter().next().unwrap().0;
        let addr = "127.0.0.1:4443".parse().unwrap();

        tokio::task::spawn(async move {
            server::run(db, server::Options { addr }).await.unwrap();
        });

        let opts = client::Options { addr };
        let (mut source, sink) = tokio::io::duplex(1024);
        let events: Vec<_> = client::run(hash, opts, sink).try_collect().await?;
        assert_eq!(events.len(), 3);
        let expect = tokio::fs::read(path).await?;
        let mut got = Vec::new();
        source.read_to_end(&mut got).await?;

        assert_eq!(expect, got);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_clients() -> Result<()> {
        let dir: PathBuf = testdir!();
        let path = dir.join("hello_world");
        let content = b"hello world!";
        let addr = "127.0.0.1:4444".parse().unwrap();

        tokio::fs::write(&path, content).await?;
        let db = server::create_db(vec![&path]).await?;
        let hash = *db.iter().next().unwrap().0;
        tokio::task::spawn(async move {
            server::run(db, server::Options { addr }).await.unwrap();
        });

        async fn run_client(hash: bao::Hash, addr: SocketAddr, content: Vec<u8>) -> Result<()> {
            let opts = client::Options { addr };
            let (mut source, sink) = tokio::io::duplex(1024);
            let events: Vec<_> = client::run(hash, opts, sink).try_collect().await?;
            assert_eq!(events.len(), 3);
            let mut got = Vec::new();
            source.read_to_end(&mut got).await?;
            assert_eq!(content, got);
            Ok(())
        }

        let mut tasks = Vec::new();
        for _i in 0..3 {
            tasks.push(tokio::task::spawn(run_client(hash, addr, content.to_vec())));
        }

        for task in tasks {
            task.await??;
        }

        Ok(())
    }
}
