use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use colored::Colorize;
use futures::{StreamExt, TryStreamExt};
use indicatif::HumanBytes;
use iroh::{
    client::quic::{Doc, Iroh},
    rpc_protocol::{DocTicket, ShareMode},
    sync_engine::{LiveEvent, Origin},
};
use iroh_sync::{store::GetFilter, AuthorId, Entry, NamespaceId};
use tokio::io::AsyncReadExt;

use crate::config::ConsoleEnv;

const MAX_DISPLAY_CONTENT_LEN: u64 = 80;

#[derive(Debug, Clone, Copy, clap::ValueEnum, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum DisplayContentMode {
    /// Displays content if small enough, otherwise it displays the content hash exclusively.
    Auto,
    /// Display the content unconditionally.
    Content,
    /// Display the contents of the hash.
    Hash,
}

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
        /// How to show the contents of the key.
        #[clap(short, long, default_value_t=DisplayContentMode::Auto)]
        mode: DisplayContentMode,
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
    pub async fn run(self, iroh: &Iroh, env: &ConsoleEnv) -> Result<()> {
        match self {
            Self::Switch { id: doc } => {
                env.set_doc(doc)?;
                println!("Active doc is now {}", fmt_short(doc.as_bytes()));
            }
            Self::New { switch } => {
                if switch && !env.is_console() {
                    bail!("The --switch flag is only supported within the Iroh console.");
                }

                let doc = iroh.docs.create().await?;
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

                let doc = iroh.docs.import(ticket).await?;
                println!("{}", doc.id());

                if switch {
                    env.set_doc(doc.id())?;
                    println!("Active doc is now {}", fmt_short(doc.id().as_bytes()));
                }
            }
            Self::List => {
                let mut stream = iroh.docs.list().await?;
                while let Some(id) = stream.try_next().await? {
                    println!("{}", id)
                }
            }
            Self::Share { doc, mode } => {
                let doc = get_doc(iroh, env, doc).await?;
                let ticket = doc.share(mode).await?;
                println!("{}", ticket);
            }
            Self::Set {
                doc,
                author,
                key,
                value,
            } => {
                let doc = get_doc(iroh, env, doc).await?;
                let author = env.author(author)?;
                let key = key.as_bytes().to_vec();
                let value = value.as_bytes().to_vec();
                let hash = doc.set_bytes(author, key, value).await?;
                println!("{}", hash);
            }
            Self::Get {
                doc,
                key,
                prefix,
                author,
                mode,
            } => {
                let doc = get_doc(iroh, env, doc).await?;
                let key = key.as_bytes().to_vec();
                let filter = match (author, prefix) {
                    (None, false) => GetFilter::Key(key),
                    (None, true) => GetFilter::Prefix(key),
                    (Some(author), true) => GetFilter::AuthorAndPrefix(author, key),
                    (Some(author), false) => {
                        // Special case: Author and key, this means single entry.
                        let entry = doc
                            .get_one(author, key)
                            .await?
                            .ok_or_else(|| anyhow!("Entry not found"))?;
                        println!("{}", fmt_entry(&doc, &entry, mode).await);
                        return Ok(());
                    }
                };

                let mut stream = doc.get_many(filter).await?;
                while let Some(entry) = stream.try_next().await? {
                    println!("{}", fmt_entry(&doc, &entry, mode).await);
                }
            }
            Self::Keys {
                doc,
                prefix,
                author,
            } => {
                let doc = get_doc(iroh, env, doc).await?;
                let filter = GetFilter::author_prefix(author, prefix);

                let mut stream = doc.get_many(filter).await?;
                while let Some(entry) = stream.try_next().await? {
                    println!(
                        "{}",
                        fmt_entry(&doc, &entry, DisplayContentMode::Auto).await
                    );
                }
            }
            Self::Watch { doc } => {
                let doc = get_doc(iroh, env, doc).await?;
                let mut stream = doc.subscribe().await?;
                while let Some(event) = stream.next().await {
                    let event = event?;
                    match event {
                        LiveEvent::InsertLocal { entry } => {
                            println!(
                                "local change:  {}",
                                fmt_entry(&doc, &entry, DisplayContentMode::Auto).await
                            )
                        }
                        LiveEvent::InsertRemote {
                            entry,
                            from,
                            content_status,
                        } => {
                            let mode = match content_status {
                                iroh_sync::ContentStatus::Complete => DisplayContentMode::Auto,
                                iroh_sync::ContentStatus::Incomplete => DisplayContentMode::Hash,
                                iroh_sync::ContentStatus::Missing => DisplayContentMode::Hash,
                            };
                            let content = fmt_entry(&doc, &entry, mode).await;
                            println!(
                                "remote change via @{}, status: {:?}: {}",
                                fmt_short(from.as_bytes()),
                                content_status,
                                content
                            )
                        }
                        LiveEvent::ContentReady { hash } => {
                            println!("content ready: {}", fmt_short(hash.as_bytes()))
                        }
                        LiveEvent::SyncFinished(event) => {
                            let origin = match event.origin {
                                Origin::Accept => "they initiated",
                                Origin::Connect(_) => "we initiated",
                            };
                            match event.result {
                                Ok(_) => println!(
                                    "synced doc {} with peer {} ({origin})",
                                    fmt_short(event.namespace),
                                    fmt_short(event.peer)
                                ),
                                Err(err) => println!(
                                    "failed to sync doc {} with peer {} ({origin}): {err}",
                                    fmt_short(event.namespace),
                                    fmt_short(event.peer)
                                ),
                            }
                        }
                        LiveEvent::NeighborUp(peer) => {
                            println!("neighbor peer up: {peer:?}");
                        }
                        LiveEvent::NeighborDown(peer) => {
                            println!("neighbor peer down: {peer:?}");
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

async fn get_doc(iroh: &Iroh, env: &ConsoleEnv, id: Option<NamespaceId>) -> anyhow::Result<Doc> {
    iroh.docs
        .get(env.doc(id)?)
        .await?
        .context("Document not found")
}

impl AuthorCommands {
    pub async fn run(self, iroh: &Iroh, env: &ConsoleEnv) -> Result<()> {
        match self {
            Self::Switch { author } => {
                env.set_author(author)?;
                println!("Active author is now {}", fmt_short(author.as_bytes()));
            }
            Self::List => {
                let mut stream = iroh.authors.list().await?;
                while let Some(author_id) = stream.try_next().await? {
                    println!("{}", author_id);
                }
            }
            Self::New { switch } => {
                if switch && !env.is_console() {
                    bail!("The --switch flag is only supported within the Iroh console.");
                }

                let author_id = iroh.authors.create().await?;
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

#[must_use = "this won't be printed, you need to print it yourself"]
async fn fmt_entry<'a>(doc: &'a Doc, entry: &'a Entry, mode: DisplayContentMode) -> String {
    let id = entry.id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>").bold();
    let author = fmt_short(id.author());

    let content = match mode {
        DisplayContentMode::Auto => {
            if entry.record().content_len() < MAX_DISPLAY_CONTENT_LEN {
                match doc.read_to_bytes(entry).await {
                    Ok(content) => String::from_utf8(content.into())
                        .unwrap_or_else(|_| String::from("<invalid UTF-8>")),
                    Err(err) => format!("<failed to get content: {err}>"),
                }
            } else {
                match doc.read(entry).await {
                    Ok(mut blob_reader) => {
                        let mut buf = Vec::with_capacity(MAX_DISPLAY_CONTENT_LEN as usize);

                        match blob_reader.read_buf(&mut buf).await {
                            Ok(_n) => match String::from_utf8(buf) {
                                Ok(mut repr) => {
                                    repr.push_str("... (shortened)");
                                    repr
                                }
                                Err(_) => String::from("<invalid UTF-8>"),
                            },
                            Err(err) => format!("<failed to get content: {err}>"),
                        }
                    }
                    Err(err) => format!("<failed to get content: {err}>"),
                }
            }
        }
        DisplayContentMode::Content => match doc.read_to_bytes(entry).await {
            Ok(content) => String::from_utf8(content.into())
                .unwrap_or_else(|_| String::from("<invalid UTF-8>")),
            Err(err) => format!("<failed to get content: {err}>"),
        },
        DisplayContentMode::Hash => {
            let hash = entry.record().content_hash();
            fmt_short(hash.as_bytes())
        }
    };

    let len = HumanBytes(entry.record().content_len());
    format!("@{author}: {key} = {content} ({len})")
}

/// Format the first 5 bytes of a byte string in bas32
pub fn fmt_short(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&hash.as_ref()[..5]);
    text.make_ascii_lowercase();
    format!("{}…", &text)
}
