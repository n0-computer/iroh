use std::collections::HashMap;
use std::path::PathBuf;

use crate::{
    config::{Config, CONFIG_FILE_NAME, ENV_PREFIX},
    status,
};
use crate::{
    gateway::{run_command as run_gateway_command, Gateway},
    p2p::{run_command as run_p2p_command, P2p},
    store::{run_command as run_store_command, Store},
};
use anyhow::{Context, Result};
use cid::Cid;
use clap::{Parser, Subcommand};
use futures::Stream;
use futures::StreamExt;
use iroh::{api, Api};
use iroh_metrics::config::Config as MetricsConfig;
use iroh_resolver::{resolver, unixfs_builder};
use iroh_rpc_client::Client;
use iroh_util::{iroh_config_path, make_config};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None, propagate_version = true)]
pub struct Cli {
    #[clap(long)]
    cfg: Option<PathBuf>,
    #[clap(long = "no-metrics")]
    no_metrics: bool,
    #[clap(subcommand)]
    command: Commands,
}

impl Cli {
    fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("metrics.debug".to_string(), self.no_metrics.to_string());
        map
    }
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// status checks the health of the different processes
    // #[clap(about = "Check the health of the different iroh processes.")]
    // Status {
    //     #[clap(short, long)]
    //     /// when true, updates the status table whenever a change in a process's status occurs
    //     watch: bool,
    // },
    Version,
    P2p(P2p),
    Store(Store),
    Gateway(Gateway),
    #[clap(about = "break up a file into block and provide those blocks on the ipfs network")]
    Add {
        path: PathBuf,
        #[clap(long, short)]
        recursive: bool,
        #[clap(long, short)]
        no_wrap: bool,
    },
    #[clap(
        about = "get content based on a Content Identifier from the ipfs network, and save it "
    )]
    Get {
        path: resolver::Path,
        #[clap(long, short)]
        output: Option<PathBuf>,
    },
}

#[cfg(not(test))]
pub async fn run_cli(cli: Cli) -> Result<()> {
    run_cli_impl(cli).await
}

// extracted this into a public function so that we don't get a lot of
// rust analyzer unused code errors, which we do if we inline this code inside
// of run_cli
pub async fn run_cli_impl(cli: Cli) -> Result<()> {
    let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path), cli.cfg.clone()];
    let config = make_config(
        // default
        Config::default(),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        cli.make_overrides_map(),
    )
    .unwrap();

    let metrics_handler = iroh_metrics::MetricsHandle::new(MetricsConfig::default())
        .await
        .expect("failed to initialize metrics");

    let client = Client::new(config.rpc_client).await?;

    let api = Api::new(&client);

    run_cli_command(&api, cli).await?;

    metrics_handler.shutdown();

    Ok(())
}

#[cfg(test)]
pub async fn run_cli(cli: Cli) -> Result<()> {
    let api = crate::fake::FakeApi::default();
    run_cli_command(&api, cli).await
}

async fn run_cli_command<A: api::Api<P, S>, P: api::P2p, S: api::Store>(
    api: &A,
    cli: Cli,
) -> Result<()> {
    match cli.command {
        // Commands::Status { watch } => {
        //     crate::status::status(client, watch).await?;
        // }
        Commands::Version => {
            println!("v{}", env!("CARGO_PKG_VERSION"));
        }
        Commands::P2p(p2p) => run_p2p_command(api.p2p()?, p2p).await?,
        Commands::Store(store) => run_store_command(api.store()?, store).await?,
        Commands::Gateway(gateway) => run_gateway_command(gateway).await?,
        Commands::Add {
            path,
            recursive,
            no_wrap,
        } => {
            todo!("Requires ClientApi modifications");
            // let cid = add(client, path, recursive, !no_wrap).await?;
            // println!("/ipfs/{}", cid);
        }
        Commands::Get { path, output } => {
            todo!("Requires ClientApi modifications");
            // let blocks = get(client.clone(), path, output);
            // tokio::pin!(blocks);
            // while let Some(block) = blocks.next().await {
            //     let (path, out) = block?;
            //     match out {
            //         OutType::Dir => {
            //             tokio::fs::create_dir_all(path).await?;
            //         }
            //         OutType::Reader(mut reader) => {
            //             if let Some(parent) = path.parent() {
            //                 tokio::fs::create_dir_all(parent).await?;
            //             }
            //             let mut f = tokio::fs::File::create(path).await?;
            //             tokio::io::copy(&mut reader, &mut f).await?;
            //         }
            //     }
            // }
        }
    };

    Ok(())
}

// TODO(ramfox): move to the `iroh` api package
async fn add(client: Client, path: PathBuf, recursive: bool, wrap: bool) -> Result<Cid> {
    let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
        client: Box::new(&client),
    };
    if path.is_dir() {
        unixfs_builder::add_dir(Some(&providing_client), &path, wrap, recursive).await
    } else if path.is_file() {
        unixfs_builder::add_file(Some(&providing_client), &path, wrap).await
    } else {
        anyhow::bail!("can only add files or directories");
    }
}

// TODO(ramfox): move to the `iroh` api package
enum OutType<T: resolver::ContentLoader> {
    Dir,
    Reader(resolver::OutPrettyReader<T>),
}

// TODO(ramfox): move to the `iroh` api package
fn get(
    client: Client,
    root: resolver::Path,
    output: Option<PathBuf>,
) -> impl Stream<Item = Result<(PathBuf, OutType<Client>)>> {
    tracing::debug!("get {:?}", root);
    let resolver = iroh_resolver::resolver::Resolver::new(client);
    let results = resolver.resolve_recursive_with_paths(root.clone());
    async_stream::try_stream! {
        tokio::pin!(results);
        while let Some(res) = results.next().await {
            let (path, out) = res?;
            let path = make_output_path(path, root.clone(), output.clone())?;
            if out.is_dir() {
                yield (path, OutType::Dir);
            } else {
                let reader = out.pretty(resolver.clone(), Default::default())?;
                yield (path, OutType::Reader(reader));
            }
        }
    }
}

// move to the `iroh` api package
// make_output_path adjusts the full path to replace the root with any given output path
// if it exists
fn make_output_path(
    full: resolver::Path,
    root: resolver::Path,
    output: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(ref output) = output {
        let root_str = &root.to_string()[..];
        let full_as_path = PathBuf::from(full.to_string());
        let path_str = full_as_path.to_str().context("invalid root path")?;
        let output_str = output.to_str().context("invalid output path")?;
        Ok(PathBuf::from(path_str.replace(root_str, output_str)))
    } else {
        // returns path as a string
        Ok(PathBuf::from(full.to_string_without_type()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_make_output_path() {
        // test with output dir
        let root = resolver::Path::from_str("/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR")
            .unwrap();
        let full = resolver::Path::from_str(
            "/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt",
        )
        .unwrap();
        let output = Some(PathBuf::from("foo"));
        let expect = PathBuf::from("foo/bar.txt");
        let got = make_output_path(full, root, output).unwrap();
        assert_eq!(expect, got);

        // test with output filepath
        let root = resolver::Path::from_str(
            "/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt",
        )
        .unwrap();
        let full = resolver::Path::from_str(
            "/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt",
        )
        .unwrap();
        let output = Some(PathBuf::from("foo/baz.txt"));
        let expect = PathBuf::from("foo/baz.txt");
        let got = make_output_path(full, root, output).unwrap();
        assert_eq!(expect, got);

        // test no output path
        let root = resolver::Path::from_str("/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR")
            .unwrap();
        let full = resolver::Path::from_str(
            "/ipfs/QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt",
        )
        .unwrap();
        let output = None;
        let expect = PathBuf::from("QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR/bar.txt");
        let got = make_output_path(full, root, output).unwrap();
        assert_eq!(expect, got);
    }
}
