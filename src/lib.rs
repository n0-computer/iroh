pub mod client;
pub mod protocol;
pub mod server;

mod tls;

pub use tls::{PeerId, PeerIdError};

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::PathBuf};

    use crate::client::Event;
    use crate::tls::PeerId;

    use super::*;
    use anyhow::Result;
    use futures::StreamExt;
    use rand::RngCore;
    use testdir::testdir;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn basics() -> Result<()> {
        let dir: PathBuf = testdir!();
        let path = dir.join("hello_world");
        tokio::fs::write(&path, "hello world!").await?;
        let db = server::create_db(vec![server::DataSource::File(path.clone())]).await?;
        let hash = *db.iter().next().unwrap().0;
        let addr = "127.0.0.1:4443".parse().unwrap();
        let mut server = server::Server::new(db);
        let peer_id = server.peer_id();

        tokio::task::spawn(async move {
            server.run(server::Options { addr }).await.unwrap();
        });

        let opts = client::Options {
            addr,
            peer_id: Some(peer_id),
        };
        let stream = client::run(hash, opts);
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
            let event = event?;
            if let Event::Receiving {
                hash: new_hash,
                mut reader,
            } = event
            {
                assert_eq!(hash, new_hash);
                let expect = tokio::fs::read(&path).await?;
                let mut got = Vec::new();
                reader.read_to_end(&mut got).await?;
                assert_eq!(expect, got);
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn sizes() -> Result<()> {
        let addr = "127.0.0.1:4445".parse().unwrap();

        let sizes = [
            10,
            100,
            1024,
            1024 * 100,
            1024 * 500,
            1024 * 1024,
            1024 * 1024 + 10,
        ];

        for size in sizes {
            println!("testing {size} bytes");

            let dir: PathBuf = testdir!();
            let path = dir.join("hello_world");

            let mut content = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut content);

            tokio::fs::write(&path, &content).await?;

            let db = server::create_db(vec![server::DataSource::File(path)]).await?;
            let hash = *db.iter().next().unwrap().0;
            let mut server = server::Server::new(db);
            let peer_id = server.peer_id();

            let server_task = tokio::task::spawn(async move {
                server.run(server::Options { addr }).await.unwrap();
            });

            let opts = client::Options {
                addr,
                peer_id: Some(peer_id),
            };
            let stream = client::run(hash, opts);
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                let event = event?;
                if let Event::Receiving {
                    hash: new_hash,
                    mut reader,
                } = event
                {
                    assert_eq!(hash, new_hash);
                    let mut got = Vec::new();
                    reader.read_to_end(&mut got).await?;
                    assert_eq!(content, got);
                }
            }

            server_task.abort();
            let _ = server_task.await;
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_clients() -> Result<()> {
        let dir: PathBuf = testdir!();
        let path = dir.join("hello_world");
        let content = b"hello world!";
        let addr = "127.0.0.1:4444".parse().unwrap();

        tokio::fs::write(&path, content).await?;
        let db = server::create_db(vec![server::DataSource::File(path)]).await?;
        let hash = *db.iter().next().unwrap().0;
        let mut server = server::Server::new(db);
        let peer_id = server.peer_id();

        tokio::task::spawn(async move {
            server.run(server::Options { addr }).await.unwrap();
        });

        async fn run_client(
            hash: bao::Hash,
            addr: SocketAddr,
            peer_id: PeerId,
            content: Vec<u8>,
        ) -> Result<()> {
            let opts = client::Options {
                addr,
                peer_id: Some(peer_id),
            };
            let stream = client::run(hash, opts);
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                let event = event?;
                if let Event::Receiving {
                    hash: new_hash,
                    mut reader,
                } = event
                {
                    assert_eq!(hash, new_hash);
                    let mut got = Vec::new();
                    reader.read_to_end(&mut got).await?;
                    assert_eq!(content, got);
                }
            }
            Ok(())
        }

        let mut tasks = Vec::new();
        for _i in 0..3 {
            tasks.push(tokio::task::spawn(run_client(
                hash,
                addr,
                peer_id,
                content.to_vec(),
            )));
        }

        for task in tasks {
            task.await??;
        }

        Ok(())
    }
}
