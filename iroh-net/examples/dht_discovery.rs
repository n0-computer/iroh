//! An example chat application using the iroh-net endpoint and
//! pkarr node discovery.
//!
//! Starting the example without args creates a server that publishes its
//! address to the DHT. Starting the example with a node id as argument
//! looks up the address of the node id in the DHT and connects to it.
//!
//! You can look at the published pkarr DNS record using <https://app.pkarr.org/>.
//!
//! To see what is going on, run with `RUST_LOG=iroh_pkarr_node_discovery=debug`.

#![allow(deprecated)]

use std::str::FromStr;

use clap::Parser;
use iroh_net::{endpoint::get_remote_node_id, Endpoint, NodeId};
use tracing::warn;
use url::Url;

const CHAT_ALPN: &[u8] = b"pkarr-discovery-demo-chat";

#[derive(Parser)]
struct Args {
    /// The node id to connect to. If not set, the program will start a server.
    node_id: Option<NodeId>,
    /// Disable using the mainline DHT for discovery and publishing.
    #[clap(long)]
    disable_dht: bool,
    /// Pkarr relay to use.
    #[clap(long, default_value = "iroh")]
    pkarr_relay: PkarrRelay,
}

#[derive(Debug, Clone)]
enum PkarrRelay {
    /// Disable pkarr relay.
    Disabled,
    /// Use the iroh pkarr relay.
    Iroh,
    /// Use a custom pkarr relay.
    Custom(Url),
}

impl FromStr for PkarrRelay {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(Self::Disabled),
            "iroh" => Ok(Self::Iroh),
            s => Ok(Self::Custom(Url::parse(s)?)),
        }
    }
}

fn build_discovery(args: Args) -> iroh_net::discovery::pkarr::dht::Builder {
    let builder = iroh_net::discovery::pkarr::dht::DhtDiscovery::builder().dht(!args.disable_dht);
    match args.pkarr_relay {
        PkarrRelay::Disabled => builder,
        PkarrRelay::Iroh => builder.n0_dns_pkarr_relay(),
        PkarrRelay::Custom(url) => builder.pkarr_relay(url),
    }
}

async fn chat_server(args: Args) -> anyhow::Result<()> {
    let secret_key = iroh_net::key::SecretKey::generate();
    let node_id = secret_key.public();
    let discovery = build_discovery(args)
        .secret_key(secret_key.clone())
        .build()?;
    let endpoint = Endpoint::builder()
        .alpns(vec![CHAT_ALPN.to_vec()])
        .secret_key(secret_key)
        .discovery(Box::new(discovery))
        .bind()
        .await?;
    let zid = pkarr::PublicKey::try_from(node_id.as_bytes())?.to_z32();
    println!("Listening on {}", node_id);
    println!("pkarr z32: {}", zid);
    println!("see https://app.pkarr.org/?pk={}", zid);
    while let Some(incoming) = endpoint.accept().await {
        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(err) => {
                warn!("incoming connection failed: {err:#}");
                // we can carry on in these cases:
                // this can be caused by retransmitted datagrams
                continue;
            }
        };
        tokio::spawn(async move {
            let connection = connecting.await?;
            let remote_node_id = get_remote_node_id(&connection)?;
            println!("got connection from {}", remote_node_id);
            // just leave the tasks hanging. this is just an example.
            let (mut writer, mut reader) = connection.accept_bi().await?;
            let _copy_to_stdout = tokio::spawn(async move {
                tokio::io::copy(&mut reader, &mut tokio::io::stdout()).await
            });
            let _copy_from_stdin =
                tokio::spawn(
                    async move { tokio::io::copy(&mut tokio::io::stdin(), &mut writer).await },
                );
            anyhow::Ok(())
        });
    }
    Ok(())
}

async fn chat_client(args: Args) -> anyhow::Result<()> {
    let remote_node_id = args.node_id.unwrap();
    let secret_key = iroh_net::key::SecretKey::generate();
    let node_id = secret_key.public();
    // note: we don't pass a secret key here, because we don't need to publish our address, don't spam the DHT
    let discovery = build_discovery(args).build()?;
    // we do not need to specify the alpn here, because we are not going to accept connections
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .discovery(Box::new(discovery))
        .bind()
        .await?;
    println!("We are {} and connecting to {}", node_id, remote_node_id);
    let connection = endpoint.connect(remote_node_id, CHAT_ALPN).await?;
    println!("connected to {}", remote_node_id);
    let (mut writer, mut reader) = connection.open_bi().await?;
    let _copy_to_stdout =
        tokio::spawn(async move { tokio::io::copy(&mut reader, &mut tokio::io::stdout()).await });
    let _copy_from_stdin =
        tokio::spawn(async move { tokio::io::copy(&mut tokio::io::stdin(), &mut writer).await });
    _copy_to_stdout.await??;
    _copy_from_stdin.await??;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.node_id.is_some() {
        chat_client(args).await?;
    } else {
        chat_server(args).await?;
    }
    Ok(())
}
