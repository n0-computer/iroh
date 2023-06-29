//! Chat over iroh-gossip
//!
//! This broadcasts signed messages over iroh-gossip and verifies
//! signatures on received messages.
//!
//! To connect to a swarm, you need to share a DERP server and know at least
//! one other peer's peer id.
//!
//! By default a new peer id is created when starting the example. To reuse your identity,
//! set the `--private-key` CLI flag with the private key printed on a previous invocation.
//!
//! You can use this with a local DERP server. To do so, run
//! `cargo run --bin derper -- --dev`
//! and then set the `-d http://localhost:3340` flag on this example.

use std::{collections::HashMap, net::SocketAddr};

use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroh_gossip::{
    net::{GossipHandle, GOSSIP_ALPN},
    proto::{Event, TopicId},
};
use iroh_net::{
    defaults::default_derp_map,
    hp::derp::{DerpMap, UseIpv4, UseIpv6},
    magic_endpoint::accept_conn,
    tls::{Keypair, PeerId},
    MagicEndpoint,
};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    private_key: Option<String>,
    #[clap(short, long)]
    topic: String,
    #[clap(short, long)]
    derp_server: Option<Url>,
    #[clap(short, long)]
    peers: Vec<PeerId>,
    #[clap(short, long)]
    name: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let keypair = match args.private_key {
        None => Keypair::generate(),
        Some(key) => parse_keypair(&key)?,
    };
    println!("> our private key: {}", fmt_secret(&keypair));

    // configure our derp map
    // TODO: this should be a one-liner
    let derp_map = match args.derp_server {
        None => default_derp_map(),
        Some(url) => {
            let derp_port = match url.port() {
                Some(port) => port,
                None => match url.scheme() {
                    "http" => 80,
                    "https" => 443,
                    _ => anyhow::bail!(
                        "Invalid scheme in DERP URL, only http: and https: schemes are supported."
                    ),
                },
            };
            DerpMap::default_from_node(url, 3478, derp_port, UseIpv4::None, UseIpv6::None)
        }
    };

    // init a peerid -> name hashmap
    let mut names = HashMap::new();

    // build our magic endpoint
    let endpoint = MagicEndpoint::builder()
        .keypair(keypair)
        .alpns(vec![GOSSIP_ALPN.to_vec()])
        .derp_map(Some(derp_map))
        .bind(SocketAddr::new([127, 0, 0, 1].into(), 0))
        .await?;
    println!("> our peer id: {}", endpoint.peer_id());

    // create the gossip protocol
    let gossip = GossipHandle::from_endpoint(endpoint.clone(), Default::default());

    // spawn our endpoint loop that forwards incoming connections to the gossiper
    tokio::spawn(endpoint_loop(endpoint.clone(), gossip.clone()));

    // join the topic with the peers provided
    let topic: TopicId = blake3::hash(args.topic.as_bytes()).into();
    println!("> joining topic {topic} with peers {:?}", args.peers);
    gossip.join(topic, args.peers).await?;
    println!("> joined! now send some gossip...");

    // broadcast our name, if set
    if let Some(name) = args.name {
        names.insert(endpoint.peer_id(), name.clone());
        let message =
            SignedMessage::sign_and_encode(endpoint.keypair(), &Message::AboutMe { name })?;
        gossip.broadcast(topic, message).await?;
    }

    // subscribe and print loop
    tokio::spawn(subscribe_loop(gossip.clone(), topic, names));

    // spawn an input thread that reads stdin
    // not using tokio here because they recommend this for "technical reasons"
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || input_loop(line_tx));

    // broadcast each line we type
    while let Some(text) = line_rx.recv().await {
        let message =
            SignedMessage::sign_and_encode(endpoint.keypair(), &Message::Message { text })?;
        gossip.broadcast(topic, message).await?;
    }

    Ok(())
}

async fn subscribe_loop(
    gossip: GossipHandle,
    topic: TopicId,
    mut names: HashMap<PeerId, String>,
) -> anyhow::Result<()> {
    let mut stream = gossip.subscribe(topic).await?;
    loop {
        let event = stream.recv().await?;
        if let Event::Received(data) = event {
            let (from, message) = SignedMessage::verify_and_decode(&data)?;
            match message {
                Message::AboutMe { name } => {
                    names.insert(from, name.clone());
                    println!("> {} is now known as {}", fmt_peer_id(&from), name);
                }
                Message::Message { text } => {
                    let name = names
                        .get(&from)
                        .map_or_else(|| fmt_peer_id(&from), String::to_string);
                    println!("{}: {}", name, text);
                }
            }
        }
    }
}

async fn endpoint_loop(endpoint: MagicEndpoint, gossip: GossipHandle) -> anyhow::Result<()> {
    while let Some(conn) = endpoint.accept().await {
        let (peer_id, alpn, conn) = accept_conn(conn).await?;
        match alpn.as_bytes() {
            GOSSIP_ALPN => gossip.handle_connection(conn).await?,
            _ => println!("> ignoring connection from {peer_id}: unsupported ALPN protocol"),
        }
    }
    Ok(())
}

fn input_loop(line_tx: tokio::sync::mpsc::Sender<String>) -> anyhow::Result<()> {
    let mut buffer = String::new();
    let stdin = std::io::stdin(); // We get `Stdin` here.
    loop {
        stdin.read_line(&mut buffer)?;
        line_tx.blocking_send(buffer.clone())?;
        buffer.clear();
    }
}

#[derive(Serialize, Deserialize)]
struct SignedMessage {
    from: PeerId,
    data: Bytes,
    signature: Signature,
}

impl SignedMessage {
    pub fn verify_and_decode(bytes: &[u8]) -> anyhow::Result<(PeerId, Message)> {
        let signed_message: Self = postcard::from_bytes(bytes)?;
        let key: VerifyingKey = signed_message.from.into();
        key.verify_strict(&signed_message.data, &signed_message.signature)?;
        let message: Message = postcard::from_bytes(&signed_message.data)?;
        Ok((signed_message.from, message))
    }

    pub fn sign_and_encode(keypair: &Keypair, message: &Message) -> anyhow::Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        let signature = keypair.secret().sign(&data);
        let from: PeerId = keypair.public().into();
        let signed_message = Self {
            from,
            data,
            signature,
        };
        let encoded = postcard::to_stdvec(&signed_message)?;
        Ok(encoded.into())
    }
}

#[derive(Serialize, Deserialize)]
enum Message {
    AboutMe { name: String },
    Message { text: String },
}

fn fmt_peer_id(input: &PeerId) -> String {
    let text = format!("{}", input);
    format!("{}…{}", &text[..5], &text[(text.len() - 2)..])
}

fn fmt_secret(keypair: &Keypair) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&keypair.secret().to_bytes());
    text.make_ascii_lowercase();
    text
}
fn parse_keypair(secret: &str) -> anyhow::Result<Keypair> {
    let bytes: [u8; 32] = data_encoding::BASE32_NOPAD
        .decode(secret.to_ascii_uppercase().as_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid secret"))?;
    let key = SigningKey::from_bytes(&bytes);
    Ok(key.into())
}
