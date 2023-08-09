use clap::Parser;
use futures::TryStreamExt;
use indicatif::HumanBytes;
use iroh::{
    rpc_protocol::{DocTicket, ProviderRequest, ProviderResponse, ShareMode},
    sync::PeerSource,
};
use iroh_sync::{
    store::{GetFilter, KeyFilter},
    sync::{AuthorId, NamespaceId, SignedEntry},
};
use quic_rpc::transport::quinn::QuinnConnection;

use super::RpcClient;

// TODO: It is a bit unfortunate that we have to drag the generics all through. Maybe box the conn?
pub type Iroh = iroh::client::Iroh<QuinnConnection<ProviderResponse, ProviderRequest>>;

#[derive(Debug, Clone, Parser)]
pub enum Commands {
    Author {
        #[clap(subcommand)]
        command: Author,
    },
    Docs {
        #[clap(subcommand)]
        command: Docs,
    },
    Doc {
        id: NamespaceId,
        #[clap(subcommand)]
        command: Doc,
    },
}

impl Commands {
    pub async fn run(self, client: RpcClient) -> anyhow::Result<()> {
        let iroh = Iroh::new(client);
        match self {
            Commands::Author { command } => command.run(iroh).await,
            Commands::Docs { command } => command.run(iroh).await,
            Commands::Doc { command, id } => command.run(iroh, id).await,
        }
    }
}

#[derive(Debug, Clone, Parser)]
pub enum Author {
    List,
    Create,
}

impl Author {
    pub async fn run(self, iroh: Iroh) -> anyhow::Result<()> {
        match self {
            Author::List => {
                let mut stream = iroh.list_authors().await?;
                while let Some(author_id) = stream.try_next().await? {
                    println!("{}", author_id);
                }
            }
            Author::Create => {
                let author_id = iroh.create_author().await?;
                println!("{}", author_id);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Parser)]
pub enum Docs {
    List,
    Create,
    // Import {
    //     key: String,
    //     #[clap(short, long)]
    //     peers: Vec<PeerSource>,
    // },
    Import { ticket: DocTicket },
}

impl Docs {
    pub async fn run(self, iroh: Iroh) -> anyhow::Result<()> {
        match self {
            Docs::Create => {
                let doc = iroh.create_doc().await?;
                println!("created {}", doc.id());
            }
            // Docs::Import { key, peers } => {
            //     let key = hex::decode(key)?
            //         .try_into()
            //         .map_err(|_| anyhow!("invalid length"))?;
            //     let ticket = DocTicket::new(key, peers);
            //     let doc = iroh.import_doc(ticket).await?;
            //     println!("imported {}", doc.id());
            // }
            Docs::Import { ticket } => {
                let doc = iroh.import_doc(ticket).await?;
                println!("imported {}", doc.id());
            }
            Docs::List => {
                let mut stream = iroh.list_docs().await?;
                while let Some(id) = stream.try_next().await? {
                    println!("{}", id)
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Parser)]
pub enum Doc {
    StartSync {
        peers: Vec<PeerSource>,
    },
    Share {
        mode: ShareMode,
    },
    /// Set an entry
    Set {
        /// Author of this entry.
        author: AuthorId,
        /// Key to the entry (parsed as UTF-8 string).
        key: String,
        /// Content to store for this entry (parsed as UTF-8 string)
        value: String,
    },
    /// Get entries by key
    ///
    /// Shows the author, content hash and content length for all entries for this key.
    Get {
        /// Key to the entry (parsed as UTF-8 string).
        key: String,
        /// If true, get all entries that start with KEY.
        #[clap(short, long)]
        prefix: bool,
        /// Filter by author.
        #[clap(short, long)]
        author: Option<AuthorId>,
        /// If true, old entries will be included. By default only the latest value for each key is
        /// shown.
        #[clap(short, long)]
        old: bool,
        // TODO: get content?
    },
    List {
        /// If true, old entries will be included. By default only the latest value for each key is
        /// shown.
        #[clap(short, long)]
        old: bool,
        /// Optional key prefix (parsed as UTF-8 string)
        prefix: Option<String>,
    },
}

impl Doc {
    pub async fn run(self, iroh: Iroh, doc_id: NamespaceId) -> anyhow::Result<()> {
        let doc = iroh.get_doc(doc_id)?;
        match self {
            Doc::StartSync { peers } => {
                doc.start_sync(peers).await?;
                println!("ok");
            }
            Doc::Share { mode } => {
                let ticket = doc.share(mode).await?;
                // println!("key:    {}", hex::encode(ticket.key));
                // println!(
                //     "peers:  {}",
                //     ticket
                //         .peers
                //         .iter()
                //         .map(|p| p.to_string())
                //         .collect::<Vec<_>>()
                //         .join(", ")
                // );
                println!("ticket: {}", ticket);
            }
            Doc::Set { author, key, value } => {
                let key = key.as_bytes().to_vec();
                let value = value.as_bytes().to_vec();
                let entry = doc.set_bytes(author, key, value).await?;
                println!("{}", fmt_entry(&entry));
            }
            Doc::Get {
                key,
                prefix,
                author,
                old,
            } => {
                let key = key.as_bytes().to_vec();
                let key = match prefix {
                    true => KeyFilter::Prefix(key),
                    false => KeyFilter::Key(key),
                };
                let filter = GetFilter {
                    latest: !old,
                    author,
                    key,
                };
                let mut stream = doc.get(filter).await?;
                while let Some(entry) = stream.try_next().await? {
                    println!("{}", fmt_entry(&entry));
                }
            }
            Doc::List { old, prefix } => {
                let key = match prefix {
                    Some(prefix) => KeyFilter::Prefix(prefix.as_bytes().to_vec()),
                    None => KeyFilter::All,
                };
                let filter = GetFilter {
                    latest: !old,
                    author: None,
                    key,
                };
                let mut stream = doc.get(filter).await?;
                while let Some(entry) = stream.try_next().await? {
                    println!("{}", fmt_entry(&entry));
                }
            }
        }
        Ok(())
    }
}

fn fmt_entry(entry: &SignedEntry) -> String {
    let id = entry.entry().id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_hash(id.author().as_bytes());
    let hash = entry.entry().record().content_hash();
    let hash = fmt_hash(hash.as_bytes());
    let len = HumanBytes(entry.entry().record().content_len());
    format!("@{author}: {key} = {hash} ({len})",)
}

fn fmt_hash(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&hash.as_ref()[..5]);
    text.make_ascii_lowercase();
    format!("{}…", &text)
}
