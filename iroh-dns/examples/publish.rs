use std::str::FromStr;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use iroh_net::{key::SecretKey, AddrInfo, NodeId};
use url::Url;

use iroh_dns::{
    packet::IROH_NODE_TXT_LABEL,
    publish::{Config, Publisher},
    resolve::{EXAMPLE_DOMAIN, IROH_TEST_DOMAIN},
};

#[derive(ValueEnum, Clone, Debug, Default, Copy)]
pub enum Env {
    /// Use the irohdns test server at testdns.iroh.link
    #[default]
    IrohTest,
    /// Use a relay listening at localhost:8080
    LocalDev,
}

/// Publish a record to an irohdns server.
///
/// You have to set the IROH_SECRET environment variable to the node secret for which to publish.
#[derive(Parser, Debug)]
struct Cli {
    /// Environment to publish to.
    #[clap(value_enum, short, long, default_value_t = Env::IrohTest)]
    env: Env,
    /// Relay URL. If set, the --env option will be ignored.
    #[clap(short, long, conflicts_with = "env")]
    relay: Option<Url>,
    /// Home Derp server to publish for this node
    #[clap(short, long)]
    derp_url: Url,
    /// Create a new node secret if IROH_SECRET is unset. Only for development / debugging.
    #[clap(short, long)]
    create: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();
    let secret_key = match std::env::var("IROH_SECRET") {
        Ok(s) => SecretKey::from_str(&s)?,
        Err(_) if args.create => {
            let s = SecretKey::generate();
            println!("Generated a new node secret. To reuse, set");
            println!("IROH_SECRET={s}");
            s
        }
        Err(_) => {
            bail!("Environtment variable IROH_SECRET is not set. To create a new secret, use the --create option.")
        }
    };
    let node_id = secret_key.public();
    println!("node: {node_id}");
    println!("derp: {}", args.derp_url);
    let config = match (args.relay, args.env) {
        (Some(pkarr_relay), _) => Config::new(secret_key, pkarr_relay),
        (None, Env::IrohTest) => Config::with_iroh_test(secret_key),
        (None, Env::LocalDev) => Config::localhost_dev(secret_key),
    };
    let publisher = Publisher::new(config);

    let info = AddrInfo {
        derp_url: Some(args.derp_url),
        direct_addresses: Default::default(),
    };
    // let an = NodeAnnounce::new(node_id, Some(args.home_derp), vec![]);
    publisher.publish_addr_info(&info).await?;
    println!("published signed record to {}!", publisher.pkarr_relay());
    match args.env {
        Env::IrohTest => println!(
            "TXT record resolvable at {}",
            node_domain(node_id, IROH_TEST_DOMAIN)
        ),
        Env::LocalDev => println!(
            "TXT record resolvable at {}",
            node_domain(node_id, EXAMPLE_DOMAIN)
        ),
    }
    Ok(())
}

fn node_domain(node_id: NodeId, origin: &str) -> String {
    format!("{}.{}.{}", IROH_NODE_TXT_LABEL, node_id, origin)
}
