use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Result};
use clap::{Parser, Subcommand};
use console::style;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use iroh_api::{AddEvent, Api, ApiExt, IpfsPath, Iroh};
use iroh_metrics::config::Config as MetricsConfig;
use iroh_util::human;

use crate::doc;
#[cfg(feature = "testing")]
use crate::fixture::get_fixture_api;
use crate::p2p::{run_command as run_p2p_command, P2p};
use crate::size::size_stream;

#[derive(Parser, Debug, Clone)]
#[clap(version, long_about = None, propagate_version = true)]
#[clap(about = "A next generation IPFS implementation: https://iroh.computer")]
#[clap(after_help = doc::IROH_LONG_DESCRIPTION)]
pub struct Cli {
    #[clap(long)]
    cfg: Option<PathBuf>,
    /// Do not track metrics
    #[clap(long)]
    no_metrics: bool,
    #[clap(subcommand)]
    command: Commands,
}

impl Cli {
    fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("metrics.debug".to_string(), (self.no_metrics).to_string());
        map
    }
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    P2p(P2p),
    #[clap(about = "Add a file or directory to iroh & make it available on IPFS")]
    Add {
        /// The path to a file or directory to be added
        path: PathBuf,
        /// Required to add a directory
        #[clap(long, short)]
        recursive: bool,
        /// Do not wrap added content with a directory
        #[clap(long)]
        no_wrap: bool,
    },
    #[clap(about = "Fetch IPFS content and write it to disk")]
    #[clap(after_help = doc::GET_LONG_DESCRIPTION )]
    Get {
        /// CID or CID/with/path/qualifier to get
        ipfs_path: IpfsPath,
        /// filesystem path to write to. Optional and defaults to $CID
        output: Option<PathBuf>,
    },
    #[clap(about = "Start local iroh services")]
    #[clap(after_help = doc::START_LONG_DESCRIPTION )]
    Start {
        service: Vec<String>,
    },
    /// status checks the health of the different processes
    #[clap(about = "Check the health of the different iroh services")]
    #[clap(after_help = doc::STATUS_LONG_DESCRIPTION)]
    Status {
        #[clap(short, long)]
        /// when true, updates the status table whenever a change in a process's status occurs
        watch: bool,
    },
    #[clap(about = "Stop local iroh services")]
    #[clap(after_help = doc::STOP_LONG_DESCRIPTION )]
    Stop {
        service: Vec<String>,
    },
}

impl Cli {
    // Rust analyzer sees this function as unused, because in development
    // mode the `testing` feature is enabled. This needs to be done in order
    // to compile the CLI with the testing feature, which is needed to create
    // trycmd tests.
    #[cfg(not(feature = "testing"))]
    pub async fn run(&self) -> Result<()> {
        // extracted the function body into its own function so it's
        // not all considered unused
        self.run_impl().await
    }

    // this version of the CLI runs in testing mode only
    #[cfg(feature = "testing")]
    pub async fn run(&self) -> Result<()> {
        let api = get_fixture_api();
        self.cli_command(&api).await
    }

    // this is a separate function and marked `allow[unused]` so
    // that we don't get Rust analyzer unused code warnings, which we do get if
    // we inline this code inside of run.
    #[allow(unused)]
    async fn run_impl(&self) -> Result<()> {
        let metrics_handler = iroh_metrics::MetricsHandle::new(MetricsConfig::default())
            .await
            .expect("failed to initialize metrics");

        let api = Iroh::new(self.cfg.as_deref(), self.make_overrides_map()).await?;

        self.cli_command(&api).await?;

        metrics_handler.shutdown();

        Ok(())
    }

    async fn cli_command(&self, api: &impl Api) -> Result<()> {
        match &self.command {
            Commands::Add {
                path,
                recursive,
                no_wrap,
            } => {
                add(api, path, *no_wrap, *recursive).await?;
            }
            Commands::Get {
                ipfs_path: path,
                output,
            } => {
                let root_path = api.get(path, output.as_deref()).await?;
                println!("Saving file(s) to {}", root_path.to_str().unwrap());
            }
            Commands::P2p(p2p) => run_p2p_command(&api.p2p()?, p2p).await?,
            Commands::Start { service } => {
                crate::services::start(api, service).await?;
            }
            Commands::Status { watch } => {
                crate::services::status(api, *watch).await?;
            }
            Commands::Stop { service } => {
                crate::services::stop(api, service).await?;
            }
        };

        Ok(())
    }
}

async fn add(api: &impl Api, path: &Path, no_wrap: bool, recursive: bool) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Path does not exist");
    }
    if !path.is_dir() && !path.is_file() {
        anyhow::bail!("Path is not a file or directory");
    }
    if path.is_dir() && !recursive {
        anyhow::bail!(
            "{} is a directory, use --recursive to add it",
            path.display()
        );
    }
    println!("{} Calculating size...", style("[1/2]").bold().dim());

    let pb = ProgressBar::new_spinner();
    let mut total_size: u64 = 0;

    pb.set_message(format!(
        "Discovered size: {}",
        human::format_bytes(total_size)
    ));
    let mut stream = Box::pin(size_stream(path));
    while let Some(size_info) = stream.next().await {
        total_size += size_info.size;
        pb.set_message(format!(
            "Discovered size: {}",
            human::format_bytes(total_size)
        ));
        pb.inc(1);
    }
    pb.finish_and_clear();

    println!(
        "{} Importing content {}...",
        style("[2/2]").bold().dim(),
        human::format_bytes(total_size)
    );

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] {wide_bar} {bytes}/{total_bytes} ({bytes_per_sec}) {msg}",
    )?);
    // show the progress bar right away, as `add` takes
    // a while before it starts ending progress reports
    pb.inc(0);

    let mut progress = api.add_stream(path, !no_wrap).await?;
    let mut root = None;
    while let Some(add_event) = progress.next().await {
        match add_event? {
            AddEvent::ProgressDelta { cid, size } => {
                root = Some(cid);
                if let Some(size) = size {
                    pb.inc(size);
                }
            }
        }
    }
    pb.finish_and_clear();
    ensure!(root.is_some(), "File processing failed");
    println!("/ipfs/{}", root.unwrap());

    Ok(())
}
