use anyhow::{bail, Result};
use clap::Parser;
use futures::{StreamExt, TryStreamExt};
use indicatif::HumanBytes;
use iroh::{
    client::quic::Iroh,
    rpc_protocol::{DocTicket, ShareMode},
    sync_engine::LiveEvent,
};
use iroh_sync::{store::GetFilter, AuthorId, Entry, NamespaceId};

use crate::config::ConsoleEnv;

const MAX_DISPLAY_CONTENT_LEN: u64 = 1024 * 1024;

#[derive(Debug, Clone, Parser)]
pub enum DocCommands {
    /// Set the active document (only works within the Iroh console).
    Switch { id: NamespaceId },
    /// Create a new document.
    New {
        /// Switch to the created document (only in the Iroh console).
        #[clap(long)]
        switch: bool,
    },
    /// Join a document from a ticket.
    Join {
        ticket: DocTicket,
        /// Switch to the joined document (only in the Iroh console).
        #[clap(long)]
        switch: bool,
    },
    /// List documents.
    List,
    /// Share a document with peers.
    Share {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `doc switch`.
        #[clap(short, long)]
        doc: Option<NamespaceId>,
        mode: ShareMode,
    },
    /// Set an entry in a document.
    Set {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `doc switch`.
        #[clap(short, long)]
        doc: Option<NamespaceId>,
        /// Author of the entry.
        ///
        /// Required unless the author is set through the IROH_AUTHOR environment variable.
        /// Within the Iroh console, the active author can also set with `author switch`.
        #[clap(short, long)]
        author: Option<AuthorId>,
        /// Key to the entry (parsed as UTF-8 string).
        key: String,
        /// Content to store for this entry (parsed as UTF-8 string)
        value: String,
    },
    /// Get entries in a document.
    ///
    /// Shows the author, content hash and content length for all entries for this key.
    Get {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `doc switch`.
        #[clap(short, long)]
        doc: Option<NamespaceId>,
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
    /// List all keys in a document.
    #[clap(alias = "ls")]
    Keys {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `doc switch`.
        #[clap(short, long)]
        doc: Option<NamespaceId>,
        /// Filter by author.
        #[clap(short, long)]
        author: Option<AuthorId>,
        /// If true, old entries will be included. By default only the latest value for each key is
        /// shown.
        #[clap(short, long)]
        old: bool,
        /// Optional key prefix (parsed as UTF-8 string)
        prefix: Option<String>,
    },
    /// Watch for changes and events on a document
    Watch {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `doc switch`.
        #[clap(short, long)]
        doc: Option<NamespaceId>,
    },
}

#[derive(Debug, Clone, Parser)]
pub enum AuthorCommands {
    /// Set the active author (only works within the Iroh console).
    Switch { author: AuthorId },
    /// Create a new author.
    New {
        /// Switch to the created author (only in the Iroh console).
        #[clap(long)]
        switch: bool,
    },
    /// List authors.
    #[clap(alias = "ls")]
    List,
}

impl DocCommands {
    pub async fn run(self, iroh: &Iroh, env: ConsoleEnv) -> Result<()> {
        match self {
            Self::Switch { id: doc } => {
                env.set_doc(doc)?;
                println!("Active doc is now {}", fmt_short(doc.as_bytes()));
            }
            Self::New { switch } => {
                if switch && !env.is_console() {
                    bail!("The --switch flag is only supported within the Iroh console.");
                }

                let doc = iroh.create_doc().await?;
                println!("{}", doc.id());

                if switch {
                    env.set_doc(doc.id())?;
                    println!("Active doc is now {}", fmt_short(doc.id().as_bytes()));
                }
            }
            Self::Join { ticket, switch } => {
                if switch && !env.is_console() {
                    bail!("The --switch flag is only supported within the Iroh console.");
                }

                let doc = iroh.import_doc(ticket).await?;
                println!("{}", doc.id());

                if switch {
                    env.set_doc(doc.id())?;
                    println!("Active doc is now {}", fmt_short(doc.id().as_bytes()));
                }
            }
            Self::List => {
                let mut stream = iroh.list_docs().await?;
                while let Some(id) = stream.try_next().await? {
                    println!("{}", id)
                }
            }
            Self::Share { doc, mode } => {
                let doc = iroh.get_doc(env.doc(doc)?).await?;
                let ticket = doc.share(mode).await?;
                println!("{}", ticket);
            }
            Self::Set {
                doc,
                author,
                key,
                value,
            } => {
                let doc = iroh.get_doc(env.doc(doc)?).await?;
                let author = env.author(author)?;
                let key = key.as_bytes().to_vec();
                let value = value.as_bytes().to_vec();
                let entry = doc.set_bytes(author, key, value).await?;
                println!("{}", fmt_entry(entry.entry()));
            }
            Self::Get {
                doc,
                key,
                prefix,
                author,
                old,
                content,
            } => {
                let doc = iroh.get_doc(env.doc(doc)?).await?;
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
                    println!("{}", fmt_entry(entry.entry()));
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
                doc,
                old,
                prefix,
                author,
            } => {
                let doc = iroh.get_doc(env.doc(doc)?).await?;
                let filter = match old {
                    true => GetFilter::all(),
                    false => GetFilter::latest(),
                };
                let mut filter = match prefix {
                    Some(prefix) => filter.with_prefix(prefix),
                    None => filter,
                };
                if let Some(author) = author {
                    filter = filter.with_author(author);
                };
                let mut stream = doc.get(filter).await?;
                while let Some(entry) = stream.try_next().await? {
                    println!("{}", fmt_entry(entry.entry()));
                }
            }
            Self::Watch { doc } => {
                let doc = iroh.get_doc(env.doc(doc)?).await?;
                let mut stream = doc.subscribe().await?;
                while let Some(event) = stream.next().await {
                    let event = event?;
                    match event {
                        LiveEvent::InsertLocal { entry } => {
                            println!("local change:  {}", fmt_entry(&entry))
                        }
                        LiveEvent::InsertRemote {
                            entry,
                            from,
                            content_status,
                        } => {
                            println!(
                                "remote change: {} (via @{}, content {:?})",
                                fmt_entry(&entry),
                                fmt_short(from.as_bytes()),
                                content_status
                            )
                        }
                        LiveEvent::ContentReady { hash } => {
                            println!("content ready: {}", fmt_short(hash.as_bytes()))
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl AuthorCommands {
    pub async fn run(self, iroh: &Iroh, env: ConsoleEnv) -> Result<()> {
        match self {
            Self::Switch { author } => {
                env.set_author(author)?;
                println!("Active author is now {}", fmt_short(author.as_bytes()));
            }
            Self::List => {
                let mut stream = iroh.list_authors().await?;
                while let Some(author_id) = stream.try_next().await? {
                    println!("{}", author_id);
                }
            }
            Self::New { switch } => {
                if switch && !env.is_console() {
                    bail!("The --switch flag is only supported within the Iroh console.");
                }

                let author_id = iroh.create_author().await?;
                println!("{}", author_id);

                if switch {
                    env.set_author(author_id)?;
                    println!("Active author is now {}", fmt_short(author_id.as_bytes()));
                }
            }
        }
        Ok(())
    }
}

fn fmt_entry(entry: &Entry) -> String {
    let id = entry.id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_short(id.author().as_bytes());
    let hash = entry.record().content_hash();
    let hash = fmt_short(hash.as_bytes());
    let len = HumanBytes(entry.record().content_len());
    format!("@{author}: {key} = {hash} ({len})",)
}

/// Format the first 5 bytes of a byte string in bas32
pub fn fmt_short(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&hash.as_ref()[..5]);
    text.make_ascii_lowercase();
    format!("{}…", &text)
}
