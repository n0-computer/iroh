use std::{collections::HashMap, fmt, net::SocketAddr, str::FromStr};

use anyhow::{anyhow, bail};
use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroh_gossip::{
    net::{GossipHandle, GOSSIP_ALPN},
    proto::{Event, TopicId},
};
use iroh_net::{
    defaults::{default_derp_map, DEFAULT_DERP_STUN_PORT},
    derp::{DerpMap, UseIpv4, UseIpv6},
    magic_endpoint::accept_conn,
    tls::{Keypair, PeerId},
    MagicEndpoint,
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use url::Url;

/// Chat over iroh-gossip
///
/// This broadcasts signed messages over iroh-gossip and verifies signatures
/// on received messages.
///
/// By default a new peer id is created when starting the example. To reuse your identity,
/// set the `--private-key` flag with the private key printed on a previous invocation.
///
/// By default, the DERP server run by n0 is used. To use a local DERP server, run
///     cargo run --bin derper --features derper -- --dev
/// in another terminal and then set the `-d http://localhost:3340` flag on this example.
#[derive(Parser, Debug)]
struct Args {
    /// Private key to derive our peer id from.
    #[clap(long)]
    private_key: Option<String>,
    /// Set a custom DERP server. By default, the DERP server hosted by n0 will be used.
    #[clap(short, long)]
    derp: Option<Url>,
    /// Disable DERP completely.
    #[clap(long)]
    no_derp: bool,
    /// Set your nickname.
    #[clap(short, long)]
    name: Option<String>,
    /// Set the bind port for our socket. By default, a random port will be used.
    #[clap(short, long, default_value = "0")]
    bind_port: u16,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// Open a chat room for a topic and print a ticket for others to join.
    ///
    /// If no topic is provided, a new topic will be created.
    Open {
        /// Optionally set the topic id (32 bytes, as base32 string).
        topic: Option<TopicId>,
    },
    /// Join a chat room from a ticket.
    Join {
        /// The ticket, as base32 string.
        ticket: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // parse the cli command
    let (topic, peers) = match &args.command {
        Command::Open { topic } => {
            let topic = topic.unwrap_or_else(|| TopicId::from_bytes(rand::random()));
            println!("> opening chat room for topic {topic}");
            (topic, vec![])
        }
        Command::Join { ticket } => {
            let Ticket { topic, peers } = Ticket::from_str(ticket)?;
            println!("> joining chat room for topic {topic:?}",);
            (topic, peers)
        }
    };

    // parse or generate our keypair
    let keypair = match args.private_key {
        None => Keypair::generate(),
        Some(key) => parse_keypair(&key)?,
    };
    println!("> our private key: {}", fmt_secret(&keypair));

    // configure our derp map
    let derp_map = match (args.no_derp, args.derp) {
        (false, None) => Some(default_derp_map()),
        (false, Some(url)) => Some(derp_map_from_url(url)?),
        (true, None) => None,
        (true, Some(_)) => bail!("You cannot set --no-derp and --derp at the same time"),
    };
    println!("> using DERP servers: {}", fmt_derp_map(&derp_map));

    // init a cell that will hold our gossip handle to be used in endpoint callbacks
    let gossip_cell: OnceCell<GossipHandle> = OnceCell::new();

    // init a channel that will emit once the initial endpoints of our local node are discovered
    // (not using a oneshot channel here because tokio::oneshot::Sender::send takes self, which
    // does not work in the on_endpoints Fn closure)
    let (initial_endpoints_tx, mut initial_endpoints_rx) = mpsc::channel(1);

    // build our magic endpoint
    let gossip_cell_clone = gossip_cell.clone();
    let endpoint = MagicEndpoint::builder()
        .keypair(keypair)
        .alpns(vec![GOSSIP_ALPN.to_vec()])
        .derp_map(derp_map)
        .on_endpoints(Box::new(move |endpoints| {
            // send our updated endpoints to the gossip protocol to be sent as PeerData to peers
            if let Some(gossip) = gossip_cell_clone.get() {
                gossip.update_endpoints(endpoints).ok();
            }
            // trigger channel send on the first endpoint update
            // (the receiver will be dropped after the first reception)
            initial_endpoints_tx.try_send(endpoints.to_vec()).ok();
        }))
        .bind(args.bind_port)
        .await?;
    println!("> our peer id: {}", endpoint.peer_id());

    // create the gossip protocol
    let gossip = GossipHandle::from_endpoint(endpoint.clone(), Default::default());
    // insert the gossip handle into the gossip cell to be used in the endpoint callbacks above
    gossip_cell.set(gossip.clone()).unwrap();

    // wait for a first endpoint update so that we know about at least one of our addrs
    initial_endpoints_rx.recv().await.unwrap();
    drop(initial_endpoints_rx);

    // print a ticket that inclues our own peer id and endpoint addresses
    let ticket = {
        let me = PeerAddr::from_endpoint(&endpoint).await?;
        let peers = peers.iter().chain([&me]).cloned().collect();
        Ticket { topic, peers }
    };
    println!("> ticket to join us: {ticket}");

    // spawn our endpoint loop that forwards incoming connections to the gossiper
    tokio::spawn(endpoint_loop(endpoint.clone(), gossip.clone()));

    // join the gossip topic by connecting to known peers, if any
    if peers.is_empty() {
        println!("> waiting for peers to join us...");
    } else {
        println!("> trying to connect to {} peers...", peers.len());
        // add the peer addrs from the ticket to our endpoint's addressbook so that they can be dialed
        for peer in &peers {
            endpoint
                .add_known_addrs(peer.peer_id, peer.derp_region, &peer.addrs)
                .await?;
        }
    };
    let peer_ids = peers.iter().map(|p| p.peer_id).collect();
    gossip.join(topic, peer_ids).await?;
    println!("> connected!");

    // broadcast our name, if set
    if let Some(name) = args.name {
        let message = Message::AboutMe { name };
        let encoded_message = SignedMessage::sign_and_encode(endpoint.keypair(), &message)?;
        gossip.broadcast(topic, encoded_message).await?;
    }

    // subscribe and print loop
    tokio::spawn(subscribe_loop(gossip.clone(), topic));

    // spawn an input thread that reads stdin
    // not using tokio here because they recommend this for "technical reasons"
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || input_loop(line_tx));

    // broadcast each line we type
    println!("> type a message and hit enter to send messages...");
    while let Some(text) = line_rx.recv().await {
        let message = Message::Message { text: text.clone() };
        let encoded_message = SignedMessage::sign_and_encode(endpoint.keypair(), &message)?;
        gossip.broadcast(topic, encoded_message).await?;
        println!("> sent: {text}");
    }

    Ok(())
}

async fn subscribe_loop(gossip: GossipHandle, topic: TopicId) -> anyhow::Result<()> {
    // init a peerid -> name hashmap
    let mut names = HashMap::new();
    // get a stream that emits updates on our topic
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
enum Message {
    AboutMe { name: String },
    Message { text: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct Ticket {
    topic: TopicId,
    peers: Vec<PeerAddr>,
}
impl Ticket {
    /// Deserializes from bytes.
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        postcard::from_bytes(bytes).map_err(Into::into)
    }
    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard::to_stdvec is infallible")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerAddr {
    peer_id: PeerId,
    addrs: Vec<SocketAddr>,
    derp_region: Option<u16>,
}

impl PeerAddr {
    pub async fn from_endpoint(endpoint: &MagicEndpoint) -> anyhow::Result<Self> {
        Ok(Self {
            peer_id: endpoint.peer_id(),
            derp_region: endpoint.my_derp().await,
            addrs: endpoint
                .local_endpoints()
                .await?
                .iter()
                .map(|ep| ep.addr)
                .collect(),
        })
    }
}

/// Serializes to base32.
impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = self.to_bytes();
        let mut text = data_encoding::BASE32_NOPAD.encode(&encoded);
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

/// Deserializes from base32.
impl FromStr for Ticket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        let slf = Self::from_bytes(&bytes)?;
        Ok(slf)
    }
}

// helpers

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
        .map_err(|_| anyhow!("Invalid secret"))?;
    let key = SigningKey::from_bytes(&bytes);
    Ok(key.into())
}
fn fmt_derp_map(derp_map: &Option<DerpMap>) -> String {
    match derp_map {
        None => "None".to_string(),
        Some(map) => map
            .regions
            .values()
            .flat_map(|region| region.nodes.iter().map(|node| node.url.to_string()))
            .collect::<Vec<_>>()
            .join(", "),
    }
}
fn derp_map_from_url(url: Url) -> anyhow::Result<DerpMap> {
    Ok(DerpMap::default_from_node(
        url,
        DEFAULT_DERP_STUN_PORT,
        UseIpv4::TryDns,
        UseIpv6::TryDns,
        0,
    ))
}
