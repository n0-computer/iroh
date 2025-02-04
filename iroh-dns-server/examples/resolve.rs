use std::net::SocketAddr;

use clap::{Parser, ValueEnum};
use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig},
    proto::xfer::Protocol,
    Resolver,
};
use iroh::{
    discovery::dns::{N0_DNS_NODE_ORIGIN_PROD, N0_DNS_NODE_ORIGIN_STAGING},
    dns::{node_info::TxtAttrs, DnsResolver},
    NodeId,
};

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
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let (resolver, origin) = match args.env {
        Env::Staging => (
            iroh::dns::default_resolver().clone(),
            N0_DNS_NODE_ORIGIN_STAGING,
        ),
        Env::Prod => (
            iroh::dns::default_resolver().clone(),
            N0_DNS_NODE_ORIGIN_PROD,
        ),
        Env::Dev => (
            resolver_with_nameserver(LOCALHOST_DNS.parse()?),
            EXAMPLE_ORIGIN,
        ),
    };
    let resolved = match args.command {
        Command::Node { node_id } => {
            TxtAttrs::<String>::lookup_by_id(&resolver, &node_id, origin).await?
        }
        Command::Domain { domain } => {
            TxtAttrs::<String>::lookup_by_name(&resolver, &domain).await?
        }
    };
    println!("resolved node {}", resolved.node_id());
    for (key, values) in resolved.attrs() {
        for value in values {
            println!("    {key}={value}");
        }
    }
    Ok(())
}

fn resolver_with_nameserver(nameserver: SocketAddr) -> DnsResolver {
    let mut config = ResolverConfig::new();
    let nameserver_config = NameServerConfig::new(nameserver, Protocol::Udp);
    config.add_name_server(nameserver_config);
    DnsResolver::from_tokio_resolver(Resolver::tokio(config, Default::default()))
}
