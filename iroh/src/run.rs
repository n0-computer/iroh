use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use crossterm::style::Stylize;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use iroh_api::{
    Api, ChunkerConfig, IpfsPath, ServiceStatus, UnixfsConfig, UnixfsEntry, DEFAULT_CHUNKS_SIZE,
};
use iroh_metrics::config::Config as MetricsConfig;
use iroh_util::{human, iroh_config_path, make_config};

use crate::config::{Config, CONFIG_FILE_NAME, ENV_PREFIX};
use crate::doc;
#[cfg(feature = "testing")]
use crate::fixture::get_fixture_api;
use crate::p2p::{run_command as run_p2p_command, P2p};
use crate::services::require_services;
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

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    P2p(P2p),
    #[clap(about = "Add a file or directory to iroh & make it available on IPFS")]
    #[clap(after_help = doc::ADD_LONG_DESCRIPTION )]
    Add {
        /// The path to a file or directory to be added
        path: PathBuf,
        /// Required to add a directory
        #[clap(long, short)]
        recursive: bool,
        /// Do not wrap added content with a directory
        #[clap(long)]
        no_wrap: bool,
        /// Don't provide added content to the network
        #[clap(long)]
        offline: bool,
        /// Select the chunker to use, when chunking data. Available chunkers are currently "fixed" and "rabin".
        #[clap(long, default_value_t = ChunkerConfig::Fixed(DEFAULT_CHUNKS_SIZE))]
        chunker: ChunkerConfig,
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
        /// Start all services
        #[clap(short, long)]
        all: bool,
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
    pub async fn run(&self) -> Result<()> {
        let config_path = iroh_config_path(CONFIG_FILE_NAME)?;
        let sources = [Some(config_path.as_path()), self.cfg.as_deref()];
        let config = make_config(
            // default
            Config::new(),
            // potential config files
            &sources,
            // env var prefix for this config
            ENV_PREFIX,
            // map of present command line arguments
            // args.make_overrides_map(),
            HashMap::<String, String>::new(),
        )
        .unwrap();

        let metrics_handler = iroh_metrics::MetricsHandle::new(MetricsConfig::default())
            .await
            .expect("failed to initialize metrics");

        #[cfg(feature = "testing")]
        let api = get_fixture_api();
        #[cfg(not(feature = "testing"))]
        let api = iroh_api::Api::new(self.cfg.as_deref(), self.make_overrides_map()).await?;

        self.cli_command(&config, &api).await?;

        metrics_handler.shutdown();

        Ok(())
    }

    #[cfg(not(feature = "testing"))]
    fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("metrics.debug".to_string(), (self.no_metrics).to_string());
        map
    }

    async fn cli_command(&self, config: &Config, api: &Api) -> Result<()> {
        match &self.command {
            Commands::Add {
                path,
                recursive,
                no_wrap,
                offline,
                chunker,
            } => {
                add(api, path, *no_wrap, *recursive, *chunker, !*offline).await?;
            }
            Commands::Get {
                ipfs_path: path,
                output,
            } => {
                let blocks = api.get(path)?;
                let root_path =
                    iroh_api::fs::write_get_stream(path, blocks, output.as_deref()).await?;
                println!("Saving file(s) to {}", root_path.to_str().unwrap());
            }
            Commands::P2p(p2p) => run_p2p_command(&api.p2p()?, p2p).await?,
            Commands::Start { service, all } => {
                let svc = match *all {
                    true => vec![
                        String::from("store"),
                        String::from("p2p"),
                        String::from("gateway"),
                    ],
                    false => match service.is_empty() {
                        true => config.start_default_services.clone(),
                        false => service.clone(),
                    },
                };
                crate::services::start(api, &svc).await?;
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

async fn add(
    api: &Api,
    path: &Path,
    no_wrap: bool,
    recursive: bool,
    chunker: ChunkerConfig,
    provide: bool,
) -> Result<()> {
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

    let mut steps = 3;
    // we require p2p for adding right now because we don't have a mechanism for
    // hydrating only the root CID to the p2p node for providing if a CID were
    // ingested offline. Offline adding should happen, but this is the current
    // path of least confusion
    let svc_status = require_services(api, BTreeSet::from(["store"])).await?;
    match (provide, svc_status.p2p.status()) {
        (true, ServiceStatus::Down) => {
            anyhow::bail!("Add provides content to the IPFS network by default, but the p2p service is not running.\n{}",
            "hint: try using the --offline flag, or run 'iroh start p2p'".yellow()
            )
        }
        (true, ServiceStatus::Unknown)
        | (true, ServiceStatus::NotServing)
        | (true, ServiceStatus::ServiceUnknown) => {
            anyhow::bail!("Add provides content to the IPFS network by default, but the p2p service is not running.\n{}",
            "hint: try using the --offline flag, or run 'iroh start p2p'".yellow()
            )
        }
        (true, ServiceStatus::Serving) => {}
        (false, _) => {
            steps -= 1;
        }
    }

    println!(
        "{} Calculating size...",
        style(format!("[1/{}]", steps)).bold().dim()
    );

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
        style(format!("[2/{}]", steps)).bold().dim(),
        human::format_bytes(total_size)
    );

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] {wide_bar} {bytes}/{total_bytes} ({bytes_per_sec}) {msg}",
    )?);
    // show the progress bar right away, as `add` takes
    // a while before it starts ending progress reports
    pb.inc(0);

    let entry = UnixfsEntry::from_path(
        path,
        UnixfsConfig {
            wrap: !no_wrap,
            chunker: Some(chunker),
        },
    )
    .await?;
    let mut progress = api.add_stream(entry).await?;
    let mut cids = Vec::new();
    while let Some(prog) = progress.next().await {
        let (cid, size) = prog?;
        cids.push(cid);
        pb.inc(size);
    }
    pb.finish_and_clear();

    let root = *cids.last().context("File processing failed")?;

    if provide {
        let pb = ProgressBar::new(cids.len().try_into().unwrap());
        // remove everything but the root
        cids.splice(0..cids.len() - 1, []);
        let rec_str = if cids.len() == 1 { "record" } else { "records" };
        println!(
            "{} Providing {} {} to the distributed hash table ...",
            style(format!("[3/{}]", steps)).bold().dim(),
            cids.len(),
            rec_str,
        );
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {wide_bar} {pos}/{len} ({per_sec}) {msg}",
            )
            .unwrap(),
        );
        pb.inc(0);
        for cid in cids {
            api.provide(cid).await?;
            pb.inc(1);
        }
        pb.finish_and_clear();
    }

    println!("/ipfs/{}", root);

    Ok(())
}
