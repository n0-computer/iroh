use std::{path::PathBuf, time::Duration};

use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use iroh_share::{Receiver, Sender, Ticket};
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
            let rpc_p2p_port = 5550;
            let rpc_store_port = 5560;
            let sender = Sender::new(port, rpc_p2p_port, rpc_store_port, &sender_db)
                .await
                .context("failed to create sender")?;

            ensure!(path.exists(), "provided file does not exist");
            ensure!(path.is_file(), "currently only supports files");

            // TODO: streaming read
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().to_owned())
                .unwrap_or_default();
            let data = tokio::fs::read(&path).await?;

            let sender_transfer = sender
                .transfer_from_data(name, data.into())
                .await
                .context("transfer")?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let ticket = sender_transfer.ticket().await.context("s: ticket")?;
            let ticket_bytes = ticket.as_bytes();
            let ticket_str = multibase::encode(multibase::Base::Base64, &ticket_bytes);
            println!("Ticket:\n{}\n", ticket_str);
            iroh_util::block_until_sigint().await;
        }
        Commands::Receive { ticket, out } => {
            println!("Receiving");

            let (_, ticket_bytes) = multibase::decode(ticket)?;
            let ticket = Ticket::from_bytes(&ticket_bytes)?;

            let sender_dir = tempfile::tempdir().unwrap();
            let sender_db = sender_dir.path().join("db");

            let port = 9991;
            let rpc_p2p_port = 5551;
            let rpc_store_port = 5561;
            let receiver = Receiver::new(port, rpc_p2p_port, rpc_store_port, &sender_db)
                .await
                .context("failed to create sender")?;
            let receiver_transfer = receiver
                .transfer_from_ticket(ticket)
                .await
                .context("failed to read transfer")?;
            let data = receiver_transfer.recv().await?;

            let out = out.unwrap_or_else(|| std::env::current_dir().expect("cannot determine cwd"));
            let path = out.join(data.name());
            tokio::fs::create_dir_all(out).await?;
            tokio::fs::write(&path, data.bytes()).await?;

            println!("Received: {}, written to: {}", data.name(), path.display());
        }
    }

    Ok(())
}
