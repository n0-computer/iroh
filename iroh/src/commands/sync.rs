use std::str::FromStr;

use anyhow::{anyhow, Result};
use clap::Parser;
use futures::TryStreamExt;
use indicatif::HumanBytes;
use iroh::{
    client::quic::Iroh,
    rpc_protocol::{DocTicket, ShareMode},
    sync::PeerSource,
};
use iroh_sync::{
    store::GetFilter,
    sync::{AuthorId, NamespaceId, SignedEntry},
};

use crate::config::env_var;

use super::RpcClient;

const MAX_DISPLAY_CONTENT_LEN: u64 = 1024 * 1024;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Parser)]
pub enum Commands {
    /// Manage document authors
    Author {
        #[clap(subcommand)]
        command: Author,
    },
    /// Manage documents
    Docs {
        #[clap(subcommand)]
        command: Docs,
    },
    /// Manage a single document
    Doc {
        id: NamespaceId,
        #[clap(subcommand)]
        command: Doc,
    },
}

impl Commands {
    pub async fn run(self, client: RpcClient) -> Result<()> {
        let iroh = Iroh::new(client);
        match self {
            Commands::Author { command } => command.run(&iroh).await,
            Commands::Docs { command } => command.run(&iroh).await,
            Commands::Doc { command, id } => {
                let doc_env = DocEnv::from_env()?;
                command.run(&iroh, id, doc_env).await
            }
        }
    }
}

#[derive(Debug, Clone, Parser)]
pub enum Author {
    /// List authors
    #[clap(alias = "ls")]
    List,
    /// Create a new author
    Create,
}

impl Author {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
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
    /// List documents
    #[clap(alias = "ls")]
    List,
    /// Create a new document
    Create,
    /// Import a document from peers
    Import { ticket: DocTicket },
}

impl Docs {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Docs::Create => {
                let doc = iroh.create_doc().await?;
                println!("created {}", doc.id());
            }
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

#[derive(Debug, Clone, Default)]
pub struct DocEnv {
    pub author: Option<AuthorId>,
}

impl DocEnv {
    pub fn from_env() -> anyhow::Result<Self> {
        let author = if let Some(author) = env_var("AUTHOR").ok() {
            Some(AuthorId::from_str(&author)?)
        } else {
            None
        };
        Ok(Self { author })
    }

    pub fn author(&self, arg: Option<AuthorId>) -> Result<AuthorId> {
        arg.or(self.author.clone())
            .ok_or_else(|| anyhow!("Author is required but not set"))
    }
}

#[derive(Debug, Clone, Parser)]
pub enum Doc {
    /// Start to synchronize a document with peers
    StartSync { peers: Vec<PeerSource> },
    /// Share a document and print a ticket to share with peers
    Share { mode: ShareMode },
    /// Set an entry
    Set {
        /// Author of this entry.
        ///
        /// Required unless the author is set through the REPL environment or the IROH_AUTHOR
        /// environment variable.
        #[clap(short, long)]
        author: Option<AuthorId>,
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

        /// Also print the content for each entry (but only if smaller than 1MB and valid UTf-8)
        #[clap(short, long)]
        content: bool,
    },
    /// List all entries in the document
    #[clap(alias = "ls")]
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
    pub async fn run(self, iroh: &Iroh, doc_id: NamespaceId, env: DocEnv) -> Result<()> {
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
                let author = env.author(author)?;
                let entry = doc.set_bytes(author, key, value).await?;
                println!("{}", fmt_entry(&entry));
            }
            Doc::Get {
                key,
                prefix,
                author,
                old,
                content,
            } => {
                let mut filter = match old {
                    true => GetFilter::all(),
                    false => GetFilter::latest(),
                };
                if let Some(author) = author {
                    filter = filter.with_author(author);
                };
                let filter = match prefix {
                    true => filter.with_prefix(key),
                    false => filter.with_key(key),
                };

                let mut stream = doc.get(filter).await?;
                while let Some(entry) = stream.try_next().await? {
                    println!("{}", fmt_entry(&entry));
                    if content {
                        if entry.content_len() < MAX_DISPLAY_CONTENT_LEN {
                            match doc.get_content_bytes(&entry).await {
                                Ok(content) => match String::from_utf8(content.into()) {
                                    Ok(s) => println!("{s}"),
                                    Err(_err) => println!("<invalid UTF-8>"),
                                },
                                Err(err) => println!("<failed to get content: {err}>"),
                            }
                        } else {
                            println!(
                                "<skipping content with len {}: too large to print>",
                                HumanBytes(entry.content_len())
                            )
                        }
                    }
                    println!();
                }
            }
            Doc::List { old, prefix } => {
                let filter = match old {
                    true => GetFilter::all(),
                    false => GetFilter::latest(),
                };
                let filter = match prefix {
                    Some(prefix) => filter.with_prefix(prefix),
                    None => filter,
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
