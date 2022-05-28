use std::io::{stdout, Write};

use crossterm::terminal::{Clear, ClearType};
use crossterm::{cursor, style, QueueableCommand};
use futures::StreamExt;

use anyhow::Result;
use iroh_rpc_client::{Client, RpcClientConfig};

pub async fn status(watch: bool) -> Result<()> {
    let client = Client::new(&RpcClientConfig::default()).await.unwrap();

    let mut stdout = stdout();
    if watch {
        let status_stream = client.watch().await;
        tokio::pin!(status_stream);
        stdout.queue(Clear(ClearType::All))?;
        while let Some(table) = status_stream.next().await {
            stdout
                .queue(cursor::RestorePosition)?
                .queue(Clear(ClearType::FromCursorUp))?
                .queue(cursor::MoveTo(0, 1))?;
            table.queue_table(&stdout)?;
            stdout
                .queue(cursor::SavePosition)?
                .queue(style::Print("\n"))?
                .flush()?;
        }
        Ok(())
    } else {
        let table = client.check().await;
        table.queue_table(&stdout)?;
        stdout.flush()?;
        Ok(())
    }
}
