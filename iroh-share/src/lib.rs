mod p2p_node;
mod receiver;
mod sender;

pub use crate::p2p_node::Ticket;
pub use crate::receiver::{Receiver, Transfer as ReceiverTransfer};
pub use crate::sender::{Sender, Transfer as SenderTransfer};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use anyhow::{Context, Result};
    use bytes::Bytes;
    use iroh_resolver::unixfs_builder::{DirectoryBuilder, FileBuilder};
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

        let sender = s::Sender::new(9990, 5550, 5560, &sender_db)
            .await
            .context("s:new")?;
        let bytes = Bytes::from(vec![1u8; 5 * 1024]);
        let sender_transfer = sender
            .transfer_from_data("foo.jpg", bytes.clone())
            .await
            .context("s: transfer")?;
        let ticket = sender_transfer.ticket();

        // the ticket is serialized, shared with the receiver and deserialized there
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver_db = receiver_dir.path().join("db");
        let receiver = r::Receiver::new(9991, 5551, 5561, &receiver_db)
            .await
            .context("r: new")?;

        // tries to discover the sender, and receive the root
        let receiver_transfer = receiver
            .transfer_from_ticket(ticket)
            .await
            .context("r: transfer")?;

        let data = receiver_transfer.recv().await.context("r: recv")?;
        assert!(data.is_dir());
        let files: Vec<_> = data.read_dir().unwrap().collect::<Result<_>>()?;
        assert_eq!(files.len(), 1);

        let file = &files[0];
        assert_eq!(file.name.unwrap(), "foo.jpg");
        // let mut content = Vec::new();
        //        data.pretty().read_to_end(&mut content).await?;
        //        assert_eq!(&content, &bytes);

        sender.close().await?;
        receiver.close().await?;

        Ok(())
    }

    async fn transfer_dir() -> Result<()> {
        println!("---- DIR ----");
        let sender_dir = tempfile::tempdir().unwrap();
        let sender_db = sender_dir.path().join("db");

        let sender = s::Sender::new(9990, 5550, 5560, &sender_db)
            .await
            .context("s:new")?;

        let mut dir_builder = DirectoryBuilder::new();
        dir_builder.name("foo");
        let mut file = FileBuilder::new();
        file.name("bar.txt").content_bytes(&b"bar"[..]);
        dir_builder.add_file(file.build().await?);

        let mut file = FileBuilder::new();
        tokio::fs::write(sender_dir.path().join("baz.txt"), vec![1; 1024 * 1000]).await?;
        let f = tokio::fs::File::open(sender_dir.path().join("baz.txt")).await?;
        file.name("baz.txt").content_reader(f);
        dir_builder.add_file(file.build().await?);

        let sender_transfer = sender
            .transfer_from_dir_builder(dir_builder)
            .await
            .context("s: transfer")?;
        let ticket = sender_transfer.ticket();

        // the ticket is serialized, shared with the receiver and deserialized there
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver_db = receiver_dir.path().join("db");
        let receiver = r::Receiver::new(9991, 5551, 5561, &receiver_db)
            .await
            .context("r: new")?;

        // tries to discover the sender, and receive the root
        let receiver_transfer = receiver
            .transfer_from_ticket(ticket)
            .await
            .context("r: transfer")?;

        let data = receiver_transfer.recv().await.context("r: recv")?;
        assert!(data.is_dir());

        let files: Vec<_> = data.read_dir().unwrap().collect::<Result<_>>()?;
        assert_eq!(files.len(), 2);
        {
            println!("reading file bar.txt");
            assert_eq!(files[0].name.unwrap(), "bar.txt");
            let file = data.read_file(&files[0]).await?;
            let mut file_content = Vec::new();
            file.pretty().read_to_end(&mut file_content).await?;
            assert_eq!(&file_content, b"bar");
        }

        {
            println!("reading file baz.txt");
            assert_eq!(files[1].name.unwrap(), "baz.txt");
            let file = data.read_file(&files[1]).await?;
            let mut file_content = Vec::new();
            file.pretty()
                .read_to_end(&mut file_content)
                .await
                .context("read_to_end")?;
            assert_eq!(&file_content, &vec![1; 1024 * 1000]);
        }

        sender.close().await?;
        receiver.close().await?;

        Ok(())
    }
}
