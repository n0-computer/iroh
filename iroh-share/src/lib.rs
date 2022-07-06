mod p2p_node;
mod receiver;
mod sender;

pub use crate::p2p_node::Ticket;
pub use crate::receiver::Receiver;
pub use crate::sender::Sender;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use bytes::Bytes;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    use receiver as r;
    use sender as s;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_transfer() -> Result<()> {
        tracing_subscriber::registry()
            .with(fmt::layer().pretty())
            .with(EnvFilter::from_default_env())
            .init();

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
        let ticket = sender_transfer.ticket().await.context("s: ticket")?;

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
        assert_eq!(data.bytes(), &bytes);
        assert_eq!(data.name(), "foo.jpg");

        Ok(())
    }
}
