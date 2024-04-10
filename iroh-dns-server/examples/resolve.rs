use std::net::SocketAddr;

use clap::{Parser, ValueEnum};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig},
    AsyncResolver,
};
use iroh_net::{
    discovery::dns::N0_DNS_NODE_ORIGIN,
    dns::{
        node_info::{lookup_by_domain, lookup_by_id},
        DnsResolver,
    },
    NodeId,
};

const LOCALHOST_DNS: &str = "127.0.0.1:5300";
const EXAMPLE_ORIGIN: &str = "irohdns.example";

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum Env {
    /// Use the system's nameservers with origin testdns.iroh.link
    #[default]
    Default,
    /// Use a localhost DNS server listening on port 5300
    Dev,
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(value_enum, short, long, default_value_t = Env::Default)]
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
    let (resolver, origin) = match args.env {
        Env::Default => (
            iroh_net::dns::default_resolver().clone(),
            N0_DNS_NODE_ORIGIN,
        ),
        Env::Dev => (
            resolver_with_nameserver(LOCALHOST_DNS.parse()?),
            EXAMPLE_ORIGIN,
        ),
    };
    let resolved = match args.command {
        Command::Node { node_id } => lookup_by_id(&resolver, &node_id, origin).await?,
        Command::Domain { domain } => lookup_by_domain(&resolver, &domain).await?,
    };
    println!("resolved node {}", resolved.node_id);
    if let Some(relay_url) = resolved.relay_url() {
        println!("    relay={relay_url}");
    }
    Ok(())
}

fn resolver_with_nameserver(nameserver: SocketAddr) -> DnsResolver {
    let mut config = ResolverConfig::new();
    let nameserver_config = NameServerConfig::new(nameserver, Protocol::Udp);
    config.add_name_server(nameserver_config);
    AsyncResolver::tokio(config, Default::default())
}
