mod data;
mod iroh;
mod receiver;
mod sender;

use cid::Cid;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

// pub use crate::receiver::{ProgressEvent, Receiver};
// pub use crate::sender::Sender;
pub use crate::receiver::ProgressEvent;

// TODO(ramfox): remove re export
pub use crate::iroh::build as build_iroh;

use anyhow::Result;
use libp2p::gossipsub::{Sha256Topic, TopicHash};
use rand::Rng;

/// Ticket describing the peer, their addresses, and the topic
/// on which to discuss the data transfer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ticket {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub topic: String,
}

impl Ticket {
    pub fn new(peer_id: PeerId, addrs: Vec<Multiaddr>) -> Self {
        let id: u64 = rand::thread_rng().gen();
        let topic = Sha256Topic::new(format!("iroh-share-{id}"))
            .hash()
            .to_string();
        Self {
            peer_id,
            addrs,
            topic,
        }
    }

    pub fn topic_hash(&self) -> TopicHash {
        TopicHash::from_raw(self.topic.clone())
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("failed to serialize")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let ticket = bincode::deserialize(bytes)?;
        Ok(ticket)
    }
}

/// Messages sent from the sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SenderMessage {
    Start {
        /// The root Cid of the content.
        root: Cid,
        /// How many individual pieces the transfer consists of.
        num_parts: usize,
    },
}

/// Messages sent from the receiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReceiverMessage {
    /// Transfer was completed successfully.
    FinishOk,
    /// Transfer failed.
    FinishError(String),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use anyhow::{Context, Result};
    use bytes::Bytes;
    use futures::TryStreamExt;
    use iroh_unixfs::builder::{DirectoryBuilder, FileBuilder};
    use rand::RngCore;
    use tokio::io::AsyncReadExt;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    use receiver as r;
    use sender as s;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_transfer() -> Result<()> {
        tracing_subscriber::registry()
            .with(fmt::layer().pretty())
            .with(EnvFilter::from_default_env())
            .init();

        transfer_file().await.context("file")?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        transfer_dir().await.context("dir")?;
        Ok(())
    }

    async fn transfer_file() -> Result<()> {
        println!("---- FILE ----");
        let sender_dir = tempfile::tempdir().unwrap();
        let sender_db = sender_dir.path().join("db");

        let sender = s::Sender::new(9990, &sender_db).await.context("s:new")?;
        let mut bytes = vec![0u8; 5 * 1024 * 1024 - 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        let bytes = Bytes::from(bytes);
        let sender_transfer = sender
            .transfer_from_data("foo.jpg", bytes.clone())
            .await
            .context("s: transfer")?;
        let ticket = sender_transfer.ticket();

        // the ticket is serialized, shared with the receiver and deserialized there
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver_db = receiver_dir.path().join("db");
        let receiver = r::Receiver::new(9991, &receiver_db)
            .await
            .context("r: new")?;

        // tries to discover the sender, and receive the root
        let mut receiver_transfer = receiver
            .transfer_from_ticket(ticket)
            .await
            .context("r: transfer")?;

        let data = receiver_transfer.recv().await.context("r: recv")?;
        assert!(data.is_dir());
        let files: Vec<_> = data.read_dir()?.unwrap().try_collect().await?;
        assert_eq!(files.len(), 1);

        let file = &files[0];
        assert_eq!(file.name.as_ref().unwrap(), "foo.jpg");

        let mut content = Vec::new();
        let file = data.read_file(&files[0]).await?;
        file.pretty()?.read_to_end(&mut content).await?;
        assert_eq!(&content, &bytes);

        // Check progress
        {
            println!("waiting for progress");
            let progress = receiver_transfer.progress()?;
            let progress: Vec<_> = progress.try_collect().await.unwrap();
            assert_eq!(progress.len(), 22);
            assert_eq!(
                progress[0],
                ProgressEvent::Piece {
                    index: 1,
                    total: 22
                }
            );
            assert_eq!(
                progress[1],
                ProgressEvent::Piece {
                    index: 2,
                    total: 22
                }
            );
        }

        // wait for the sender to report done
        println!("waiting for done");
        sender_transfer.done().await?;
        receiver_transfer.finish().await?;

        Ok(())
    }

    async fn transfer_dir() -> Result<()> {
        println!("---- DIR ----");
        let sender_dir = tempfile::tempdir().unwrap();
        let sender_db = sender_dir.path().join("db");

        let sender = s::Sender::new(9990, &sender_db).await.context("s:new")?;

        let file_1 = FileBuilder::new()
            .name("bar.txt")
            .content_bytes(&b"bar"[..])
            .build()
            .await?;

        let mut bytes = vec![0u8; 5 * 1024 * 1024 - 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        tokio::fs::write(sender_dir.path().join("baz.txt"), &bytes).await?;
        let f = tokio::fs::File::open(sender_dir.path().join("baz.txt")).await?;
        let file_2 = FileBuilder::new()
            .name("baz.txt")
            .content_reader(f)
            .build()
            .await?;
        let dir_builder = DirectoryBuilder::new()
            .name("foo")
            .add_file(file_1)
            .add_file(file_2);

        let sender_transfer = sender
            .transfer_from_dir_builder(dir_builder)
            .await
            .context("s: transfer")?;
        let ticket = sender_transfer.ticket();

        // the ticket is serialized, shared with the receiver and deserialized there
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver_db = receiver_dir.path().join("db");
        let receiver = r::Receiver::new(9991, &receiver_db)
            .await
            .context("r: new")?;

        // tries to discover the sender, and receive the root
        let mut receiver_transfer = receiver
            .transfer_from_ticket(ticket)
            .await
            .context("r: transfer")?;

        let data = receiver_transfer.recv().await.context("r: recv")?;
        assert!(data.is_dir());

        let files: Vec<_> = data.read_dir()?.unwrap().try_collect().await?;
        assert_eq!(files.len(), 2);
        {
            println!("reading file bar.txt");
            assert_eq!(files[0].name.as_ref().unwrap(), "bar.txt");
            let file = data.read_file(&files[0]).await?;
            let mut file_content = Vec::new();
            file.pretty()?.read_to_end(&mut file_content).await?;
            assert_eq!(&file_content, b"bar");
        }

        {
            println!("reading file baz.txt");
            assert_eq!(files[1].name.as_ref().unwrap(), "baz.txt");
            let file = data.read_file(&files[1]).await?;
            let mut file_content = Vec::new();
            file.pretty()?
                .read_to_end(&mut file_content)
                .await
                .context("read_to_end")?;
            assert_eq!(&file_content, &bytes);
        }

        // Check progress
        {
            let progress = receiver_transfer.progress()?;
            let progress: Vec<_> = progress.try_collect().await.unwrap();
            assert_eq!(progress.len(), 23);
            assert_eq!(
                progress[0],
                ProgressEvent::Piece {
                    index: 1,
                    total: 23
                }
            );
            assert_eq!(
                progress[1],
                ProgressEvent::Piece {
                    index: 2,
                    total: 23
                }
            );
            assert_eq!(
                progress[2],
                ProgressEvent::Piece {
                    index: 3,
                    total: 23
                }
            );
            assert_eq!(
                progress[3],
                ProgressEvent::Piece {
                    index: 4,
                    total: 23
                }
            );
            assert_eq!(
                progress[4],
                ProgressEvent::Piece {
                    index: 5,
                    total: 23
                }
            );
            assert_eq!(
                progress[5],
                ProgressEvent::Piece {
                    index: 6,
                    total: 23
                }
            );
            assert_eq!(
                progress[6],
                ProgressEvent::Piece {
                    index: 7,
                    total: 23
                }
            );
        }

        // wait for the sender to report done
        sender_transfer.done().await?;
        receiver_transfer.finish().await?;

        Ok(())
    }
}
