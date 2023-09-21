use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use futures::{StreamExt, TryStreamExt};
use indicatif::HumanBytes;
use iroh::{
    client::quic::{Doc, Iroh},
    rpc_protocol::{DocTicket, ShareMode},
    sync_engine::{LiveEvent, Origin},
};
use iroh_sync::{store::GetFilter, AuthorId, Entry, NamespaceId};

use crate::{commands::add::aggregate_add_response, config::ConsoleEnv};

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
        /// Optional key prefix (parsed as UTF-8 string)
        prefix: Option<String>,
    },
    /// Import data into a document
    Import {
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
        /// Prefex to add to imported entries (parsed as UTF-8 string). Defaults to no prefix
        #[clap(long)]
        prefix: Option<String>,
        /// Path to a local file or directory to import
        ///
        /// Pathnames will be used as the document key
        #[clap(long)]
        path: String,
        /// If true, don't copy the file into iroh, reference the existing file instead
        ///
        /// Moving a file imported with in-place will result in data corruption
        #[clap(short, long)]
        in_place: bool,
    },
    /// Export data from a document
    Export {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `doc switch`.
        #[clap(short, long)]
        doc: Option<NamespaceId>,
        /// Key to the entry (parsed as UTF-8 string)
        #[clap(short, long)]
        key: String,
        /// Path to export to
        #[clap(short, long)]
        path: String,
    },
    /// Output changes and events on a document
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
                content,
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
                        print_entry(&doc, &entry, content).await?;
                        return Ok(());
                    }
                };

                let mut stream = doc.get_many(filter).await?;
                while let Some(entry) = stream.try_next().await? {
                    print_entry(&doc, &entry, content).await?;
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
                    println!("{}", fmt_entry(&entry));
                }
            }
            Self::Import {
                doc,
                author,
                prefix,
                path,
                in_place,
            } => {
                let doc = get_doc(iroh, env, doc).await?;
                let author = env.author(author)?;
                let mut prefix = prefix.unwrap_or_else(|| String::from(""));

                if prefix.ends_with('/') {
                    prefix.pop();
                }
                let root = canonicalize_path(&path)?.canonicalize()?;
                let files = walkdir::WalkDir::new(&root).into_iter();
                // TODO: parallelize
                let mut counts = (0, 0);
                for file in files {
                    let file = file?;
                    if file.file_type().is_file() {
                        let relative = file.path().strip_prefix(&root)?.to_string_lossy();
                        if relative.is_empty() {
                            print!("invalid file path: {:?}", file.path());
                            continue;
                        }
                        let key = if prefix.is_empty() {
                            relative.to_string()
                        } else {
                            format!("{prefix}/{relative}")
                        };

                        let stream = iroh
                            .blobs
                            .add_from_path(file.path().into(), in_place)
                            .await?;
                        // TODO(b5): horrible hack b/c add_from_path creates a collection
                        // and we really just want the raw blob
                        let (_, entries) = aggregate_add_response(stream).await?;
                        let hash = entries[0].hash;
                        doc.set_hash(author, key.into(), hash).await?;
                        // println!(
                        //     "> imported {relative}: {} ({})",
                        //     fmt_hash(hash),
                        //     HumanBytes(len)
                        // );
                        counts.0 += 1;
                        counts.1 += entries[0].size;
                    }
                }
                println!(
                    "Imported {} entries totaling {}",
                    counts.0,
                    HumanBytes(counts.1)
                );
            }
            Self::Export { doc, key, path } => {
                let doc = get_doc(iroh, env, doc).await?;
                let key = key.as_bytes().to_vec();
                let filter = GetFilter::Key(key);
                // let path = canonicalize_path(&path)?.canonicalize()?;
                let path: PathBuf = path.into();

                let mut stream = doc.get_many(filter).await?;
                while let Some(entry) = stream.try_next().await? {
                    match doc.read_to_bytes(&entry).await {
                        Ok(content) => {
                            // println!("writing to {}", path.display());
                            std::fs::write(path.clone(), content).unwrap();
                        }
                        Err(err) => println!("<failed to get content: {err}>"),
                    }
                }
            }
            Self::Watch { doc } => {
                let doc = get_doc(iroh, env, doc).await?;
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
                                    "failed to synced doc {} with peer {} ({origin}): {err}",
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

fn fmt_entry(entry: &Entry) -> String {
    let id = entry.id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_short(id.author());
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

async fn print_entry(doc: &Doc, entry: &Entry, content: bool) -> anyhow::Result<()> {
    println!("{}", fmt_entry(entry));
    if content {
        if entry.content_len() < MAX_DISPLAY_CONTENT_LEN {
            match doc.read_to_bytes(entry).await {
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
    Ok(())
}

fn canonicalize_path(path: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(shellexpand::tilde(&path).to_string());
    Ok(path)
}
