pub mod args;
pub mod discovery;
pub mod io;
pub mod iroh_bytes_util;
pub mod options;
pub mod protocol;
pub mod tracker;

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use clap::Parser;
use iroh::util::fs::load_secret_key;
use iroh_net::{
    magic_endpoint::{get_alpn, get_peer_id},
    AddrInfo, MagicEndpoint, PeerAddr,
};
use tokio_util::task::LocalPoolHandle;

use crate::{
    args::{AnnounceArgs, Args, Commands, QueryArgs, ServerArgs},
    io::{setup_logging, tracker_home, tracker_path},
    options::Options,
    protocol::{
        Announce, AnnounceKind, Query, QueryFlags, Request, Response, REQUEST_SIZE_LIMIT,
        TRACKER_ALPN,
    },
    tracker::Tracker,
};

pub type NodeId = iroh_net::key::PublicKey;

pub static VERBOSE: AtomicBool = AtomicBool::new(false);

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        if crate::VERBOSE.load(std::sync::atomic::Ordering::Relaxed) {
            println!($($arg)*);
        }
    };
}

/// Wait until the endpoint has figured out it's own DERP region.
async fn await_derp_region(endpoint: &MagicEndpoint) -> anyhow::Result<()> {
    let t0 = Instant::now();
    loop {
        let addr = endpoint.my_addr().await?;
        if addr.derp_region().is_some() {
            break;
        }
        if t0.elapsed() > Duration::from_secs(10) {
            anyhow::bail!("timeout waiting for DERP region");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

async fn create_endpoint(
    key: iroh_net::key::SecretKey,
    port: u16,
) -> anyhow::Result<MagicEndpoint> {
    // let pkarr_relay_discovery = discovery::PkarrRelayDiscovery::new(key.clone(), PKARR_RELAY_URL.parse().unwrap());
    let region_discover = discovery::HardcodedRegionDiscovery::new(2);
    iroh_net::MagicEndpoint::builder()
        .secret_key(key)
        .discovery(Box::new(region_discover))
        .alpns(vec![TRACKER_ALPN.to_vec()])
        .bind(port)
        .await
}

fn write_defaults() -> anyhow::Result<()> {
    let default_path = tracker_path("server.config.default.toml")?;
    crate::io::save_to_file(&Options::default(), &default_path)?;
    Ok(())
}

async fn server(args: ServerArgs) -> anyhow::Result<()> {
    let rt = tokio::runtime::Handle::current();
    let tpc = LocalPoolHandle::new(2);
    let rt = iroh_bytes::util::runtime::Handle::new(rt, tpc);
    let home = tracker_home()?;
    VERBOSE.store(!args.quiet, Ordering::Relaxed);
    println!("tracker starting using {}", tracker_home()?.display());
    let key_path = tracker_path("server.key")?;
    let key = load_secret_key(key_path).await?;
    let endpoint = create_endpoint(key, args.port).await?;
    let config_path = tracker_path("server.config.toml")?;
    write_defaults()?;
    let mut options = if config_path.exists() {
        let config = std::fs::read_to_string(config_path)?;
        toml::from_str(&config)?
    } else {
        Options::default()
    };
    options.make_paths_relative(&home);
    let db = Tracker::new(options)?;
    await_derp_region(&endpoint).await?;
    let addr = endpoint.my_addr().await?;
    println!("listening on {:?}", addr);
    println!("peer addr: {}", addr.peer_id);
    let db2 = db.clone();
    let endpoint2 = endpoint.clone();
    let _task = rt
        .local_pool()
        .spawn_pinned(move || db2.probe_loop(endpoint2));
    while let Some(connecting) = endpoint.accept().await {
        tracing::info!("got connecting");
        let db = db.clone();
        tokio::spawn(async move {
            let Ok((pk, h, conn)) = accept_conn(connecting).await else {
                tracing::error!("error accepting connection");
                return;
            };
            tracing::info!("got connection from {} {}", pk, h);
            if let Err(cause) = db.handle_connection(conn).await {
                tracing::error!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

/// Accept an incoming connection and extract the client-provided [`NodeId`] and ALPN protocol.
pub async fn accept_conn(
    mut conn: quinn::Connecting,
) -> anyhow::Result<(NodeId, String, quinn::Connection)> {
    let alpn = get_alpn(&mut conn).await?;
    tracing::info!("awaiting conn");
    let conn = conn.await?;
    tracing::info!("got conn");
    let peer_id = get_peer_id(&conn).await?;
    Ok((peer_id, alpn, conn))
}

async fn announce(args: AnnounceArgs) -> anyhow::Result<()> {
    // todo: uncomment once the connection problems are fixed
    // for now, a random node id is more reliable.
    // let key = load_secret_key(tracker_path("client.key")?).await?;
    let key = iroh_net::key::SecretKey::generate();
    let endpoint = create_endpoint(key, 11112).await?;
    println!("announce {:?}", args);
    println!("trying to connect to {:?}", args.tracker);
    let info = PeerAddr {
        peer_id: args.tracker,
        info: AddrInfo {
            derp_region: Some(2),
            direct_addresses: Default::default(),
        },
    };
    let connection = endpoint.connect(info, TRACKER_ALPN).await?;
    println!("connected to {:?}", connection.remote_address());
    let (mut send, mut recv) = connection.open_bi().await?;
    println!("opened bi stream");
    let kind = if args.partial {
        AnnounceKind::Partial
    } else {
        AnnounceKind::Complete
    };
    let peer = if let Some(peer) = args.host {
        peer
    } else if let Some(peer) = args.content.peer() {
        peer
    } else {
        anyhow::bail!("either peer or ticket must be specified {:?}", args.content);
    };
    let content = [args.content.hash_and_format()].into_iter().collect();
    let announce = Announce {
        host: peer,
        kind,
        content,
    };
    let request = Request::Announce(announce);
    let request = postcard::to_stdvec(&request)?;
    println!("sending announce");
    send.write_all(&request).await?;
    send.finish().await?;
    let _response = recv.read_to_end(REQUEST_SIZE_LIMIT).await?;
    Ok(())
}

async fn query(args: QueryArgs) -> anyhow::Result<()> {
    // todo: uncomment once the connection problems are fixed
    // for now, a random node id is more reliable.
    // let key = load_secret_key(tracker_path("client.key")?).await?;
    let key = iroh_net::key::SecretKey::generate();
    let endpoint = create_endpoint(key, args.port.unwrap_or_default()).await?;
    let query = Query {
        content: args.content.hash_and_format(),
        flags: QueryFlags {
            complete: !args.partial,
            validated: args.validated,
        },
    };
    let info = PeerAddr {
        peer_id: args.tracker,
        info: AddrInfo {
            derp_region: Some(2),
            direct_addresses: Default::default(),
        },
    };
    println!("trying to connect to tracker at {:?}", args.tracker);
    let connection = endpoint.connect(info, TRACKER_ALPN).await?;
    println!("connected to {:?}", connection.remote_address());
    let (mut send, mut recv) = connection.open_bi().await?;
    println!("opened bi stream");
    let request = Request::Query(query);
    let request = postcard::to_stdvec(&request)?;
    println!("sending query");
    send.write_all(&request).await?;
    send.finish().await?;
    let response = recv.read_to_end(REQUEST_SIZE_LIMIT).await?;
    let response = postcard::from_bytes::<Response>(&response)?;
    match response {
        Response::QueryResponse(response) => {
            println!("content {}", response.content);
            for peer in response.hosts {
                println!("- peer {}", peer);
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    setup_logging();
    let args = Args::parse();
    match args.command {
        Commands::Server(args) => server(args).await,
        Commands::Announce(args) => announce(args).await,
        Commands::Query(args) => query(args).await,
    }
}
