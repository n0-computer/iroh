use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use sendme::{client, server};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
#[clap(about = "Send data.")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Serve the data from the given path
    #[clap(about = "Serve the data from the given path")]
    Server {
        paths: Vec<PathBuf>,
        #[clap(long, short)]
        /// Optional port, efaults to 4433.
        port: Option<u16>,
    },
    /// Fetch some data
    #[clap(about = "Fetch the data from the hash")]
    Client {
        hash: bao::Hash,
        #[clap(long, short)]
        /// Option address of the server, defaults to 127.0.0.1:4433.
        addr: Option<SocketAddr>,
        #[clap(long, short)]
        /// Option path to save the file, defaults to using the hash as the name.
        out: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Client { hash, addr, out } => {
            println!("Fetching: {}", hash.to_hex());
            let opts = client::Options { addr };

            let pb = indicatif::ProgressBar::new_spinner();

            // Write file out
            let outpath = out.unwrap_or_else(|| hash.to_string().into());
            let file = tokio::fs::File::create(outpath).await?;
            let out = tokio::io::BufWriter::new(file);
            // wrap for progress bar
            let mut wrapped_out = pb.wrap_async_write(out);

            let stats = client::run(hash, opts, &mut wrapped_out).await?;

            pb.finish_with_message(format!(
                "Data size: {}MiB\nTime Elapsed: {:.4}s\n{:.2}MBit/s",
                stats.data_len / 1024 / 1024,
                stats.elapsed.as_secs_f64(),
                stats.mbits
            ));
        }
        Commands::Server { paths, port } => {
            let db = server::create_db(paths.iter().map(|p| p.as_path()).collect()).await?;
            let opts = server::Options { port };
            server::run(db, opts).await?
        }
    }

    Ok(())
}
