use clap::{Parser, ValueEnum};
use iroh::{
    discovery::dns::{N0_DNS_NODE_ORIGIN_PROD, N0_DNS_NODE_ORIGIN_STAGING},
    dns::DnsResolver,
    NodeId,
};
use n0_snafu::TestResult as Result;

const LOCALHOST_DNS: &str = "127.0.0.1:5300";
const EXAMPLE_ORIGIN: &str = "irohdns.example";

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum Env {
    /// Use the system's nameservers with origin domain of the n0 staging DNS server
    #[default]
    Staging,
    /// Use the system's nameservers with origin domain of the n0 production DNS server
    Prod,
    /// Use a localhost DNS server listening on port 5300
    Dev,
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(value_enum, short, long, default_value_t = Env::Staging)]
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
async fn main() -> Result<()> {
    let args = Cli::parse();
    let (resolver, origin) = match args.env {
        Env::Staging => (DnsResolver::new(), N0_DNS_NODE_ORIGIN_STAGING),
        Env::Prod => (DnsResolver::new(), N0_DNS_NODE_ORIGIN_PROD),
        Env::Dev => (
            DnsResolver::with_nameserver(LOCALHOST_DNS.parse().expect("localhost DNS")),
            EXAMPLE_ORIGIN,
        ),
    };
    let resolved = match args.command {
        Command::Node { node_id } => resolver.lookup_node_by_id(&node_id, origin).await?,
        Command::Domain { domain } => resolver.lookup_node_by_domain_name(&domain).await?,
    };
    println!("resolved node {}", resolved.node_id);
    if let Some(url) = resolved.relay_url() {
        println!("    relay={url}")
    }
    for addr in resolved.direct_addresses() {
        println!("    addr={addr}")
    }
    if let Some(user_data) = resolved.user_data() {
        println!("    user-data={user_data}")
    }
    Ok(())
}
