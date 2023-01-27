mod blobs;
pub mod get;
pub mod protocol;
pub mod provider;

mod bao_slice_decoder;
mod tls;

pub use tls::{Keypair, PeerId, PeerIdError, PublicKey, SecretKey, Signature};

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::PathBuf};

    use crate::get::Event;
    use crate::protocol::AuthToken;
    use crate::tls::PeerId;

    use super::*;
    use anyhow::Result;
    use futures::StreamExt;
    use rand::RngCore;
    use testdir::testdir;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn basics() -> Result<()> {
        let port: u16 = 4443;
        transfer_data(
            vec![("hello_world", "hello world!".as_bytes().to_vec())],
            port,
        )
        .await
    }

    #[tokio::test]
    async fn multi_file() -> Result<()> {
        let file_opts = vec![
            ("1", 10),
            ("2", 1024),
            ("3", 1024 * 1024),
            // overkill, but it works! Just annoying to wait for
            // ("4", 1024 * 1024 * 90),
        ];
        transfer_random_data(file_opts, 4446).await
    }

    #[tokio::test]
    async fn sizes() -> Result<()> {
        let sizes = [
            0,
            10,
            100,
            1024,
            1024 * 100,
            1024 * 500,
            1024 * 1024,
            1024 * 1024 + 10,
        ];
        let port: u16 = 4445;

        for size in sizes {
            transfer_random_data(vec![("hello_world", size)], port).await?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn empty_files() -> Result<()> {
        // try to transfer as many files as possible without hitting a limit
        // booo 400 is too small :(
        let num_files = 400;
        let mut file_opts = Vec::new();
        for i in 0..num_files {
            file_opts.push((i.to_string(), 0));
        }
        transfer_random_data(file_opts, 4447).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_clients() -> Result<()> {
        let dir: PathBuf = testdir!();
        let filename = "hello_world";
        let path = dir.join(filename);
        let content = b"hello world!";
        let addr = "127.0.0.1:4444".parse().unwrap();

        tokio::fs::write(&path, content).await?;
        // hash of the transfer file
        let data = tokio::fs::read(&path).await?;
        let (_, expect_hash) = bao::encode::outboard(&data);
        let expect_name = Some(filename.to_string());

        let (db, hash) = provider::create_db(vec![provider::DataSource::File(path)]).await?;
        let provider = provider::Provider::builder(db).bind_addr(addr).spawn()?;

        async fn run_client(
            hash: bao::Hash,
            token: AuthToken,
            file_hash: bao::Hash,
            name: Option<String>,
            addr: SocketAddr,
            peer_id: PeerId,
            content: Vec<u8>,
        ) -> Result<()> {
            let opts = get::Options {
                addr,
                peer_id: Some(peer_id),
            };
            let stream = get::run(hash, token, opts);
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                let event = event?;
                if let Event::Receiving {
                    hash: got_hash,
                    mut reader,
                    name: got_name,
                } = event
                {
                    assert_eq!(file_hash, got_hash);
                    let mut got = Vec::new();
                    reader.read_to_end(&mut got).await?;
                    assert_eq!(content, got);
                    assert_eq!(name, got_name);
                }
            }
            Ok(())
        }

        let mut tasks = Vec::new();
        for _i in 0..3 {
            tasks.push(tokio::task::spawn(run_client(
                hash,
                provider.auth_token(),
                expect_hash,
                expect_name.clone(),
                addr,
                provider.peer_id(),
                content.to_vec(),
            )));
        }

        futures::future::join_all(tasks).await;

        Ok(())
    }

    // Run the test creating random data for each blob, using the size specified by the file
    // options
    // TODO: use random ports
    async fn transfer_random_data<S>(file_opts: Vec<(S, usize)>, port: u16) -> Result<()>
    where
        S: Into<String> + std::fmt::Debug + std::cmp::PartialEq,
    {
        let file_opts = file_opts
            .into_iter()
            .map(|(name, size)| {
                let mut content = vec![0u8; size];
                rand::thread_rng().fill_bytes(&mut content);
                (name, content)
            })
            .collect();
        transfer_data(file_opts, port).await
    }

    // Run the test for a vec of filenames and blob data
    // TODO: use random ports
    async fn transfer_data<S>(file_opts: Vec<(S, Vec<u8>)>, port: u16) -> Result<()>
    where
        S: Into<String> + std::fmt::Debug + std::cmp::PartialEq,
    {
        let dir: PathBuf = testdir!();

        // create and save files
        let mut files = Vec::new();
        let mut expects = Vec::new();

        for opt in file_opts.into_iter() {
            let (name, data) = opt;

            let name = name.into();
            let path = dir.join(name.clone());
            // get expected hash of file
            let (_, hash) = bao::encode::outboard(&data);

            tokio::fs::write(&path, data).await?;
            files.push(provider::DataSource::File(path.clone()));

            // keep track of expected values
            expects.push((Some(name), path, hash));
        }

        let (db, collection_hash) = provider::create_db(files).await?;

        let addr = format!("127.0.0.1:{port}").parse().unwrap();
        let provider = provider::Provider::builder(db).bind_addr(addr).spawn()?;

        let opts = get::Options {
            addr,
            peer_id: Some(provider.peer_id()),
        };
        let stream = get::run(collection_hash, provider.auth_token(), opts);
        tokio::pin!(stream);

        let mut i = 0;
        while let Some(event) = stream.next().await {
            let event = event?;
            if let Event::Receiving {
                hash: got_hash,
                mut reader,
                name: got_name,
            } = event
            {
                let (expect_name, path, expect_hash) = expects.get(i).unwrap();
                assert_eq!(*expect_hash, got_hash);
                let expect = tokio::fs::read(&path).await?;
                let mut got = Vec::new();
                reader.read_to_end(&mut got).await?;
                assert_eq!(expect, got);
                assert_eq!(*expect_name, got_name);
                i += 1;
            }
        }

        provider.abort();
        let _ = provider.join().await;
        Ok(())
    }
}
