use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use futures::stream::StreamExt;
use iroh_share::{ProgressEvent, Receiver, Sender, Ticket};
use tokio::io::AsyncWriteExt;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Sends data
    #[clap(arg_required_else_help = true)]
    Send {
        /// The data to send
        path: PathBuf,
    },
    /// Receives data
    #[clap(arg_required_else_help = true)]
    Receive {
        /// The encoded ticket string
        ticket: String,
        /// Where to write the received data to
        #[clap(long)]
        out: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().pretty())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    match args.command {
        Commands::Send { path } => {
            println!("Sending: {}", path.display());

            // TODO: allow db specification
            let sender_dir = tempfile::tempdir().unwrap();
            let sender_db = sender_dir.path().join("db");

            let port = 9990;
            let sender = Sender::new(port, &sender_db)
                .await
                .context("failed to create sender")?;

            ensure!(path.exists(), "provided file does not exist");
            ensure!(path.is_file(), "currently only supports files");

            // TODO: streaming read
            let name = path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("missing file name"))?;
            let name = name
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("file name must be valid utf8"))?;

            let data = tokio::fs::read(&path).await?;
            let sender_transfer = sender
                .transfer_from_data(name, data.into())
                .await
                .context("transfer")?;

            let ticket = sender_transfer.ticket();
            let ticket_bytes = ticket.as_bytes();
            let ticket_str = multibase::encode(multibase::Base::Base64, &ticket_bytes);
            println!("Ticket:\n{ticket_str}\n");
            sender_transfer.done().await?;
        }
        Commands::Receive { ticket, out } => {
            println!("Receiving");

            let (_, ticket_bytes) = multibase::decode(ticket)?;
            let ticket = Ticket::from_bytes(&ticket_bytes)?;

            let sender_dir = tempfile::tempdir().unwrap();
            let sender_db = sender_dir.path().join("db");

            let port = 9991;
            let receiver = Receiver::new(port, &sender_db)
                .await
                .context("failed to create sender")?;
            let mut receiver_transfer = receiver
                .transfer_from_ticket(&ticket)
                .await
                .context("failed to read transfer")?;
            let data = receiver_transfer.recv().await?;
            let mut progress = receiver_transfer.progress()?;

            tokio::spawn(async move {
                while let Some(ev) = progress.next().await {
                    match ev {
                        Ok(ProgressEvent::Piece { index, total }) => {
                            println!("transferred: {index}/{total}");
                        }
                        Err(e) => {
                            eprintln!("transfer failed: {e}");
                        }
                    }
                }
            });

            let mut out_dir = std::env::current_dir()?;
            if let Some(out) = out {
                out_dir = out_dir.join(out);
            }
            tokio::fs::create_dir_all(&out_dir)
                .await
                .with_context(|| format!("failed to create {}", out_dir.display()))?;

            let out = tokio::fs::canonicalize(out_dir).await?;

            let mut reader = data.read_dir()?.unwrap();
            while let Some(link) = reader.next().await {
                let link = link?;
                let file_content = data.read_file(&link).await?;
                let path = out.join(link.name.unwrap_or_default());
                println!("Writing {}", path.display());
                let mut file = tokio::fs::File::create(&path)
                    .await
                    .with_context(|| format!("create file: {}", path.display()))?;
                let mut content = file_content.pretty()?;
                tokio::io::copy(&mut content, &mut file)
                    .await
                    .context("copy")?;
                file.flush().await?;
            }

            receiver_transfer.finish().await?;
            println!("Received all data, written to: {}", out.display());
        }
    }

    Ok(())
}
