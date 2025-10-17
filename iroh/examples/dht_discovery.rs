//! An example chat application using the iroh endpoint and
//! pkarr endpoint discovery.
//!
//! Starting the example without args creates a server that publishes its
//! address to the DHT. Starting the example with an endpoint id as argument
//! looks up the address of the endpoint id in the DHT and connects to it.
//!
//! You can look at the published pkarr DNS record using <https://app.pkarr.org/>.
//!
//! To see what is going on, run with `RUST_LOG=iroh_pkarr_endpoint_discovery=debug`.
use std::str::FromStr;

use clap::Parser;
use iroh::{Endpoint, EndpointId};
use n0_snafu::ResultExt;
use tracing::warn;
use url::Url;

const CHAT_ALPN: &[u8] = b"pkarr-discovery-demo-chat";

#[derive(Parser)]
struct Args {
    /// The endpoint id to connect to. If not set, the program will start a server.
    endpoint_id: Option<EndpointId>,
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
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(Self::Disabled),
            "iroh" => Ok(Self::Iroh),
            s => Ok(Self::Custom(Url::parse(s)?)),
        }
    }
}

fn build_discovery(args: Args) -> iroh::discovery::pkarr::dht::Builder {
    let builder = iroh::discovery::pkarr::dht::DhtDiscovery::builder().dht(!args.disable_dht);
    match args.pkarr_relay {
        PkarrRelay::Disabled => builder,
        PkarrRelay::Iroh => builder.n0_dns_pkarr_relay(),
        PkarrRelay::Custom(url) => builder.pkarr_relay(url),
    }
}

async fn chat_server(args: Args) -> n0_snafu::Result<()> {
    let secret_key = iroh::SecretKey::generate(&mut rand::rng());
    let endpoint_id = secret_key.public();
    let discovery = build_discovery(args);
    let endpoint = Endpoint::builder()
        .alpns(vec![CHAT_ALPN.to_vec()])
        .secret_key(secret_key)
        .discovery(discovery)
        .bind()
        .await?;
    let zid = pkarr::PublicKey::try_from(endpoint_id.as_bytes())
        .e()?
        .to_z32();
    println!("Listening on {endpoint_id}");
    println!("pkarr z32: {zid}");
    println!("see https://app.pkarr.org/?pk={zid}");
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
            let connection = connecting.await.e()?;
            let remote_endpoint_id = connection.remote_id();
            println!("got connection from {remote_endpoint_id}");
            // just leave the tasks hanging. this is just an example.
            let (mut writer, mut reader) = connection.accept_bi().await.e()?;
            let _copy_to_stdout = tokio::spawn(async move {
                tokio::io::copy(&mut reader, &mut tokio::io::stdout()).await
            });
            let _copy_from_stdin =
                tokio::spawn(
                    async move { tokio::io::copy(&mut tokio::io::stdin(), &mut writer).await },
                );
            Ok::<_, n0_snafu::Error>(())
        });
    }
    Ok(())
}

async fn chat_client(args: Args) -> n0_snafu::Result<()> {
    let remote_endpoint_id = args.endpoint_id.unwrap();
    let secret_key = iroh::SecretKey::generate(&mut rand::rng());
    let endpoint_id = secret_key.public();
    // note: we don't pass a secret key here, because we don't need to publish our address, don't spam the DHT
    let discovery = build_discovery(args).no_publish();
    // we do not need to specify the alpn here, because we are not going to accept connections
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .discovery(discovery)
        .bind()
        .await?;
    println!("We are {endpoint_id} and connecting to {remote_endpoint_id}");
    let connection = endpoint.connect(remote_endpoint_id, CHAT_ALPN).await?;
    println!("connected to {remote_endpoint_id}");
    let (mut writer, mut reader) = connection.open_bi().await.e()?;
    let _copy_to_stdout =
        tokio::spawn(async move { tokio::io::copy(&mut reader, &mut tokio::io::stdout()).await });
    let _copy_from_stdin =
        tokio::spawn(async move { tokio::io::copy(&mut tokio::io::stdin(), &mut writer).await });
    _copy_to_stdout.await.e()?.e()?;
    _copy_from_stdin.await.e()?.e()?;
    Ok(())
}

#[tokio::main]
async fn main() -> n0_snafu::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.endpoint_id.is_some() {
        chat_client(args).await?;
    } else {
        chat_server(args).await?;
    }
    Ok(())
}
