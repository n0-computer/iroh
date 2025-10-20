use clap::{Parser, ValueEnum};
use iroh::{
    EndpointId,
    discovery::dns::{N0_DNS_ENDPOINT_ORIGIN_PROD, N0_DNS_ENDPOINT_ORIGIN_STAGING},
    dns::DnsResolver,
};
use n0_snafu::{Result, ResultExt};

const DEV_DNS_SERVER: &str = "127.0.0.1:5300";
const DEV_DNS_ORIGIN_DOMAIN: &str = "irohdns.example";

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
    dns_server: Option<String>,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Resolve endpoint info by endpoint id.
    Endpoint {
        /// The endpoint id to resolve.
        endpoint_id: EndpointId,
        /// Use a custom domain when resolving endpoint info via DNS.
        #[clap(long)]
        dns_origin_domain: Option<String>,
    },
    /// Resolve endpoint info by domain.
    Domain { domain: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let resolver = if let Some(host) = args.dns_server {
        let addr = tokio::net::lookup_host(host)
            .await
            .e()?
            .next()
            .context("failed to resolve DNS server address")?;
        DnsResolver::with_nameserver(addr)
    } else {
        match args.env {
            Env::Staging | Env::Prod => DnsResolver::new(),
            Env::Dev => {
                DnsResolver::with_nameserver(DEV_DNS_SERVER.parse().expect("valid address"))
            }
        }
    };
    let resolved = match args.command {
        Command::Endpoint {
            endpoint_id,
            dns_origin_domain,
        } => {
            let origin_domain = match (&dns_origin_domain, args.env) {
                (Some(domain), _) => domain,
                (None, Env::Prod) => N0_DNS_ENDPOINT_ORIGIN_PROD,
                (None, Env::Staging) => N0_DNS_ENDPOINT_ORIGIN_STAGING,
                (None, Env::Dev) => DEV_DNS_ORIGIN_DOMAIN,
            };
            resolver
                .lookup_endpoint_by_id(&endpoint_id, origin_domain)
                .await?
        }
        Command::Domain { domain } => resolver.lookup_endpoint_by_domain_name(&domain).await?,
    };
    println!("resolved endpoint {}", resolved.endpoint_id);
    for url in resolved.relay_urls() {
        println!("    relay={url}")
    }
    for addr in resolved.ip_addresses() {
        println!("    addr={addr}")
    }
    if let Some(user_data) = resolved.user_data() {
        println!("    user-data={user_data}")
    }
    Ok(())
}
