use clap::Parser;
use clap::ValueEnum;
use iroh_dns::resolve::{Config, Resolver};
use iroh_net::NodeId;

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum Env {
    /// Use cloudflare and the irohdns test server at testdns.iroh.link
    #[default]
    IrohTest,
    /// Use a localhost domain server listening on port 5353
    LocalDev,
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(value_enum, short, long, default_value_t = Env::IrohTest)]
    env: Env,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Resolve node info by node id.
    Node { node_id: NodeId },
    /// Resolve node info by domain.
    Domain { domain: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let config = match args.env {
        Env::IrohTest => Config::with_cloudflare_and_iroh_test(),
        Env::LocalDev => Config::localhost_dev(),
    };
    let resolver = Resolver::new(config)?;
    match args.command {
        Command::Node { node_id } => {
            let addr = resolver.resolve_node_by_id(node_id).await?;
            let derp_url = addr.derp_url.map(|u| u.to_string()).unwrap_or_default();
            println!("node_id:  {node_id}");
            println!("derp_url: {derp_url}");
        }
        Command::Domain { domain } => {
            let addr = resolver.resolve_node_by_domain(&domain).await?;
            let node_id = addr.node_id;
            let derp_url = addr
                .info
                .derp_url
                .map(|u| u.to_string())
                .unwrap_or_default();
            println!("node_id:  {node_id}");
            println!("derp_url: {derp_url}");
        }
    }
    Ok(())
}
