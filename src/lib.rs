pub mod blobs;
pub mod get;
pub mod protocol;
pub mod provider;

mod bao_slice_decoder;
mod tls;
mod util;

pub use tls::{Keypair, PeerId, PeerIdError, PublicKey, SecretKey, Signature};
pub use util::Hash;

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        path::PathBuf,
        sync::{atomic::AtomicUsize, Arc},
    };

    use crate::tls::PeerId;
    use crate::{protocol::AuthToken, util::Hash};

    use super::*;
    use anyhow::Result;
    use rand::RngCore;
    use testdir::testdir;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn basics() -> Result<()> {
        transfer_data(vec![("hello_world", "hello world!".as_bytes().to_vec())]).await
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
        transfer_random_data(file_opts).await
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

        for size in sizes {
            transfer_random_data(vec![("hello_world", size)]).await?;
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
        transfer_random_data(file_opts).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_clients() -> Result<()> {
        let dir: PathBuf = testdir!();
        let filename = "hello_world";
        let path = dir.join(filename);
        let content = b"hello world!";
        let addr = "127.0.0.1:0".parse().unwrap();

        tokio::fs::write(&path, content).await?;
        // hash of the transfer file
        let data = tokio::fs::read(&path).await?;
        let (_, expect_hash) = bao::encode::outboard(&data);
        let expect_name = filename.to_string();

        let (db, hash) =
            provider::create_collection(vec![provider::DataSource::File(path)]).await?;
        let provider = provider::Provider::builder(db).bind_addr(addr).spawn()?;

        async fn run_client(
            hash: Hash,
            token: AuthToken,
            file_hash: Hash,
            name: String,
            addr: SocketAddr,
            peer_id: PeerId,
            content: Vec<u8>,
        ) -> Result<()> {
            let opts = get::Options {
                addr,
                peer_id: Some(peer_id),
            };
            let content = &content;
            let name = &name;
            get::run(
                hash,
                token,
                opts,
                || async move { Ok(()) },
                |_collection| async move { Ok(()) },
                |got_hash, mut reader, got_name| async move {
                    assert_eq!(file_hash, got_hash);
                    let mut got = Vec::new();
                    reader.read_to_end(&mut got).await?;
                    assert_eq!(content, &got);
                    assert_eq!(*name, got_name);

                    Ok(reader)
                },
            )
            .await?;

            Ok(())
        }

        let mut tasks = Vec::new();
        for _i in 0..3 {
            tasks.push(tokio::task::spawn(run_client(
                hash,
                provider.auth_token(),
                expect_hash.into(),
                expect_name.clone(),
                provider.listen_addr(),
                provider.peer_id(),
                content.to_vec(),
            )));
        }

        futures::future::join_all(tasks).await;

        Ok(())
    }

    // Run the test creating random data for each blob, using the size specified by the file
    // options
    async fn transfer_random_data<S>(file_opts: Vec<(S, usize)>) -> Result<()>
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
        transfer_data(file_opts).await
    }

    // Run the test for a vec of filenames and blob data
    async fn transfer_data<S>(file_opts: Vec<(S, Vec<u8>)>) -> Result<()>
    where
        S: Into<String> + std::fmt::Debug + std::cmp::PartialEq,
    {
        let dir: PathBuf = testdir!();

        // create and save files
        let mut files = Vec::new();
        let mut expects = Vec::new();
        let num_blobs = file_opts.len();

        for opt in file_opts.into_iter() {
            let (name, data) = opt;

            let name = name.into();
            let path = dir.join(name.clone());
            // get expected hash of file
            let (_, hash) = bao::encode::outboard(&data);
            let hash = Hash::from(hash);

            tokio::fs::write(&path, data).await?;
            files.push(provider::DataSource::File(path.clone()));

            // keep track of expected values
            expects.push((name, path, hash));
        }

        let (db, collection_hash) = provider::create_collection(files).await?;

        let addr = "127.0.0.1:0".parse().unwrap();
        let provider = provider::Provider::builder(db).bind_addr(addr).spawn()?;
        let mut provider_events = provider.subscribe();
        let events_task = tokio::task::spawn(async move {
            let mut events = Vec::new();
            while let Ok(event) = provider_events.recv().await {
                events.push(event);
            }
            events
        });

        let opts = get::Options {
            addr: provider.listen_addr(),
            peer_id: Some(provider.peer_id()),
        };

        let i = AtomicUsize::new(0);
        let expects = Arc::new(expects);

        get::run(
            collection_hash,
            provider.auth_token(),
            opts,
            || async move { Ok(()) },
            |collection| async move {
                assert_eq!(collection.blobs.len(), num_blobs);
                Ok(())
            },
            |got_hash, mut reader, got_name| {
                let i = &i;
                let expects = expects.clone();
                async move {
                    let iv = i.load(std::sync::atomic::Ordering::SeqCst);
                    let (expect_name, path, expect_hash) = expects.get(iv).unwrap();
                    assert_eq!(*expect_hash, got_hash);
                    let expect = tokio::fs::read(&path).await?;
                    let mut got = Vec::new();
                    reader.read_to_end(&mut got).await?;
                    assert_eq!(expect, got);
                    assert_eq!(*expect_name, got_name);
                    i.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(reader)
                }
            },
        )
        .await?;

        provider.abort();
        let _ = provider.join().await;

        let events = events_task.await.unwrap();
        assert_eq!(events.len(), 3);

        Ok(())
    }
}
