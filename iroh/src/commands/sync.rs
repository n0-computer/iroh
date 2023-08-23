use anyhow::Result;
use clap::{Parser, Subcommand};
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

use crate::config::ConsoleEnv;

use super::RpcClient;

const MAX_DISPLAY_CONTENT_LEN: u64 = 1024 * 1024;

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Manage documents
    Doc {
        #[clap(subcommand)]
        command: DocCommands,
    },

    /// Manage document authors
    Author {
        #[clap(subcommand)]
        command: AuthorCommands,
    },
}

impl Commands {
    pub async fn run(self, client: RpcClient, env: ConsoleEnv) -> Result<()> {
        let iroh = Iroh::new(client);
        match self {
            Self::Doc { command } => command.run(&iroh, env).await,
            Self::Author { command } => command.run(&iroh).await,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Parser)]
pub enum DocCommands {
    /// Create a new document
    Init,
    /// Import a document from peers
    Import { ticket: DocTicket },
    /// List documents
    List,
    /// Start to synchronize a document with peers
    Sync {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `set-doc`.
        #[clap(short, long)]
        doc_id: Option<NamespaceId>,

        peers: Vec<PeerSource>,
    },
    /// Share a document and print a ticket to share with peers
    Share {
        /// Set the document
        #[clap(short, long)]
        doc_id: Option<NamespaceId>,
        mode: ShareMode,
    },
    /// Set an entry
    Set {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `set-doc`.
        #[clap(short, long)]
        doc_id: Option<NamespaceId>,
        /// Author of this entry.
        ///
        /// Required unless the author is set through the IROH_AUTHOR environment variable.
        /// Within the Iroh console, the active author can also set with `set-author`.
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
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `set-doc`.
        #[clap(short, long)]
        doc_id: Option<NamespaceId>,
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
    Keys {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `set-doc`.
        #[clap(short, long)]
        doc_id: Option<NamespaceId>,
        /// If true, old entries will be included. By default only the latest value for each key is
        /// shown.
        #[clap(short, long)]
        old: bool,
        /// Optional key prefix (parsed as UTF-8 string)
        prefix: Option<String>,
    },
}

impl DocCommands {
    pub async fn run(self, iroh: &Iroh, env: ConsoleEnv) -> Result<()> {
        match self {
            Self::Init => {
                let doc = iroh.create_doc().await?;
                println!("{}", doc.id());
            }
            Self::Import { ticket } => {
                let doc = iroh.import_doc(ticket).await?;
                println!("{}", doc.id());
            }
            Self::List => {
                let mut stream = iroh.list_docs().await?;
                while let Some(id) = stream.try_next().await? {
                    println!("{}", id)
                }
            }
            Self::Sync { doc_id, peers } => {
                let doc = iroh.get_doc(env.doc(doc_id)?)?;
                doc.start_sync(peers).await?;
                println!("ok");
            }
            Self::Share { doc_id, mode } => {
                let doc = iroh.get_doc(env.doc(doc_id)?)?;
                let ticket = doc.share(mode).await?;
                println!("{}", ticket);
            }
            Self::Set {
                doc_id,
                author,
                key,
                value,
            } => {
                let doc = iroh.get_doc(env.doc(doc_id)?)?;
                let author = env.author(author)?;
                let key = key.as_bytes().to_vec();
                let value = value.as_bytes().to_vec();
                let entry = doc.set_bytes(author, key, value).await?;
                println!("{}", fmt_entry(&entry));
            }
            Self::Get {
                doc_id,
                key,
                prefix,
                author,
                old,
                content,
            } => {
                let doc = iroh.get_doc(env.doc(doc_id)?)?;
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
            Self::Keys {
                doc_id,
                old,
                prefix,
            } => {
                let doc = iroh.get_doc(env.doc(doc_id)?)?;
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

#[derive(Debug, Clone, Parser)]
pub enum AuthorCommands {
    /// Create a new author
    Create,
    /// List authors
    #[clap(alias = "ls")]
    List,
}

impl AuthorCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            AuthorCommands::List => {
                let mut stream = iroh.list_authors().await?;
                while let Some(author_id) = stream.try_next().await? {
                    println!("{}", author_id);
                }
            }
            AuthorCommands::Create => {
                let author_id = iroh.create_author().await?;
                println!("{}", author_id);
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
