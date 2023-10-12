use std::{
    cell::RefCell,
    collections::BTreeMap,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use colored::Colorize;
use dialoguer::Confirm;
use futures::{Stream, StreamExt, TryStreamExt};
use indicatif::{HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressStyle};
use tokio::io::AsyncReadExt;

use iroh::{
    client::quic::{Doc, Iroh},
    rpc_protocol::{DocTicket, SetTagOption, ShareMode, WrapOption},
    sync_engine::{LiveEvent, Origin},
    util::fs::{path_content_info, PathContent},
};
use iroh_bytes::{provider::AddProgress, Hash, Tag};
use iroh_sync::{store::GetFilter, AuthorId, Entry, NamespaceId};

use crate::config::ConsoleEnv;

const MAX_DISPLAY_CONTENT_LEN: u64 = 80;

#[derive(Debug, Clone, Copy, clap::ValueEnum, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum DisplayContentMode {
    /// Displays the content if small enough, otherwise it displays the content hash.
    Auto,
    /// Display the content unconditionally.
    Content,
    /// Display the hash of the content.
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
    /// Delete all entries below a key prefix.
    Del {
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
        /// Prefix to delete. All entries whose key starts with or is equal to the prefix will be
        /// deleted.
        prefix: String,
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
        /// How to show the contents of the keys.
        #[clap(short, long, default_value_t=DisplayContentMode::Hash)]
        mode: DisplayContentMode,
    },
    /// Import data into a document
    Import {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also be set with `doc switch`.
        #[clap(short, long)]
        doc: Option<NamespaceId>,
        /// Author of the entry.
        ///
        /// Required unless the author is set through the IROH_AUTHOR environment variable.
        /// Within the Iroh console, the active author can also be set with `author switch`.
        #[clap(short, long)]
        author: Option<AuthorId>,
        /// Prefix to add to imported entries (parsed as UTF-8 string). Defaults to no prefix
        #[clap(long)]
        prefix: Option<String>,
        /// Path to a local file or directory to import
        ///
        /// Pathnames will be used as the document key
        path: String,
        /// If true, don't copy the file into iroh, reference the existing file instead
        ///
        /// Moving a file imported with `in-place` will result in data corruption
        #[clap(short, long)]
        in_place: bool,
    },
    /// Export data from a document
    Export {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also be set with `doc switch`.
        #[clap(short, long)]
        doc: Option<NamespaceId>,
        /// Author of the entry.
        ///
        /// Required unless the author is set through the IROH_AUTHOR environment variable.
        /// Within the Iroh console, the active author can also be set with `author switch`.
        #[clap(short, long)]
        author: Option<AuthorId>,
        /// Key to the entry (parsed as UTF-8 string)
        key: String,
        /// Path to export to
        #[clap(short, long)]
        out: String,
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
    /// Stop syncing a document.
    Leave {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `doc switch`.
        doc: Option<NamespaceId>,
    },
    /// Delete a document from the local node.
    ///
    /// This is a destructive operation. Both the document secret key and all entries in the
    /// document will be permanently deleted from the node's storage. Content blobs will be deleted
    /// through garbage collection unless they are referenced from another document or tag.
    Drop {
        /// Document to operate on.
        ///
        /// Required unless the document is set through the IROH_DOC environment variable.
        /// Within the Iroh console, the active document can also set with `doc switch`.
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
            Self::Del {
                doc,
                author,
                prefix,
            } => {
                let doc = get_doc(iroh, env, doc).await?;
                let author = env.author(author)?;
                let prompt =
                    format!("Deleting all entries whose key starts with {prefix}. Continue?");
                if Confirm::new()
                    .with_prompt(prompt)
                    .interact()
                    .unwrap_or(false)
                {
                    let key = prefix.as_bytes().to_vec();
                    let removed = doc.del(author, key).await?;
                    println!("Deleted {removed} entries.");
                    println!(
                        "Inserted an empty entry for author {} with key {prefix}.",
                        fmt_short(author)
                    );
                } else {
                    println!("Aborted.")
                }
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
                mode,
            } => {
                let doc = get_doc(iroh, env, doc).await?;
                let filter = GetFilter::author_prefix(author, prefix);

                let mut stream = doc.get_many(filter).await?;
                while let Some(entry) = stream.try_next().await? {
                    println!("{}", fmt_entry(&doc, &entry, mode).await);
                }
            }
            Self::Leave { doc } => {
                let doc = get_doc(iroh, env, doc).await?;
                doc.leave().await?;
                println!("Doc {} is now inactive", fmt_short(doc.id()));
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
                let tag = tag_from_file_name(&root)?;

                let root0 = root.clone();
                println!("Preparing import...");
                // get information about the directory or file we are trying to import
                // and confirm with the user that they still want to import the file
                let PathContent { size, files } =
                    tokio::task::spawn_blocking(|| path_content_info(root0)).await??;
                let prompt = format!("Import {files} files totaling {}?", HumanBytes(size));
                if !Confirm::new()
                    .with_prompt(prompt)
                    .interact()
                    .unwrap_or(false)
                {
                    println!("Aborted.");
                    return Ok(());
                } else {
                    print!("\r");
                }

                let stream = iroh
                    .blobs
                    .add_from_path(
                        root.clone(),
                        in_place,
                        SetTagOption::Named(tag.clone()),
                        WrapOption::NoWrap,
                    )
                    .await?;
                let root_prefix = match root.parent() {
                    Some(p) => p.to_path_buf(),
                    None => PathBuf::new(),
                };
                let start = Instant::now();
                import_coordinator(doc, author, root_prefix, prefix, stream, size, files).await?;
                println!("Success! ({})", HumanDuration(start.elapsed()));
            }
            Self::Export {
                doc,
                author,
                key,
                out,
            } => {
                let doc = get_doc(iroh, env, doc).await?;
                let author = env.author(author)?;
                let key_str = key.clone();
                let key = key.as_bytes().to_vec();
                let path: PathBuf = canonicalize_path(&out)?;
                let entry = doc
                    .get_one(author, key)
                    .await?
                    .ok_or_else(|| anyhow!("<could not find entry {key_str}>"))?;
                match doc.read(&entry).await {
                    Ok(mut content) => {
                        if let Some(dir) = path.parent() {
                            if let Err(err) = std::fs::create_dir_all(dir) {
                                println!(
                                    "<unable to create directory for {}: {err}>",
                                    path.display()
                                );
                            }
                        };
                        let pb = ProgressBar::new(content.size());
                        pb.set_style(ProgressStyle::default_bar()
                                .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})").unwrap()
                                .progress_chars("=>-"));
                        let file = tokio::fs::File::create(path.clone()).await?;
                        if let Err(err) =
                            tokio::io::copy(&mut content, &mut pb.wrap_async_write(file)).await
                        {
                            pb.finish_and_clear();
                            println!("<unable to write to file {}: {err}>", path.display())
                        } else {
                            pb.finish_and_clear();
                            println!("wrote '{key_str}' to {}", path.display());
                        }
                    }
                    Err(err) => println!("<failed to get content: {err}>"),
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
                            let content = match content_status {
                                iroh_sync::ContentStatus::Complete => {
                                    fmt_entry(&doc, &entry, DisplayContentMode::Auto).await
                                }
                                iroh_sync::ContentStatus::Incomplete => {
                                    let (Ok(content) | Err(content)) =
                                        fmt_content(&doc, &entry, DisplayContentMode::Hash).await;
                                    format!("<incomplete: {} ({})>", content, human_len(&entry))
                                }
                                iroh_sync::ContentStatus::Missing => {
                                    let (Ok(content) | Err(content)) =
                                        fmt_content(&doc, &entry, DisplayContentMode::Hash).await;
                                    format!("<missing: {} ({})>", content, human_len(&entry))
                                }
                            };
                            println!(
                                "remote change via @{}: {}",
                                fmt_short(from.as_bytes()),
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
                        LiveEvent::Closed => println!("document closed"),
                    }
                }
            }
            Self::Drop { doc } => {
                let doc = get_doc(iroh, env, doc).await?;
                println!(
                    "Deleting a document will permanently remove the document secret key, all document entries, \n\
                    and all content blobs which are not referenced from other docs or tags."
                );
                let prompt = format!("Delete document {}?", fmt_short(doc.id()));
                if Confirm::new()
                    .with_prompt(prompt)
                    .interact()
                    .unwrap_or(false)
                {
                    iroh.docs.drop_doc(doc.id()).await?;
                    println!("Doc {} has been deleted.", fmt_short(doc.id()));
                } else {
                    println!("Aborted.")
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

/// Format the content. If an error occurs it's returned in a formatted, friendly way.
async fn fmt_content(doc: &Doc, entry: &Entry, mode: DisplayContentMode) -> Result<String, String> {
    let read_failed = |err: anyhow::Error| format!("<failed to get content: {err}>");
    let encode_hex = |err: std::string::FromUtf8Error| format!("0x{}", hex::encode(err.as_bytes()));
    let as_utf8 = |buf: Vec<u8>| String::from_utf8(buf).map(|repr| format!("\"{repr}\""));

    match mode {
        DisplayContentMode::Auto => {
            if entry.record().content_len() < MAX_DISPLAY_CONTENT_LEN {
                // small content: read fully as UTF-8
                let bytes = doc.read_to_bytes(entry).await.map_err(read_failed)?;
                Ok(as_utf8(bytes.into()).unwrap_or_else(encode_hex))
            } else {
                // large content: read just the first part as UTF-8
                let mut blob_reader = doc.read(entry).await.map_err(read_failed)?;
                let mut buf = Vec::with_capacity(MAX_DISPLAY_CONTENT_LEN as usize + 5);

                blob_reader
                    .read_buf(&mut buf)
                    .await
                    .map_err(|io_err| read_failed(io_err.into()))?;
                let mut repr = as_utf8(buf).unwrap_or_else(encode_hex);
                // let users know this is not shown in full
                repr.push_str("...");
                Ok(repr)
            }
        }
        DisplayContentMode::Content => {
            // read fully as UTF-8
            let bytes = doc.read_to_bytes(entry).await.map_err(read_failed)?;
            Ok(as_utf8(bytes.into()).unwrap_or_else(encode_hex))
        }
        DisplayContentMode::Hash => {
            let hash = entry.record().content_hash();
            Ok(fmt_short(hash.as_bytes()))
        }
    }
}

/// Human bytes for the contents of this entry.
fn human_len(entry: &Entry) -> HumanBytes {
    HumanBytes(entry.record().content_len())
}

#[must_use = "this won't be printed, you need to print it yourself"]
async fn fmt_entry(doc: &Doc, entry: &Entry, mode: DisplayContentMode) -> String {
    let id = entry.id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>").bold();
    let author = fmt_short(id.author());
    let (Ok(content) | Err(content)) = fmt_content(doc, entry, mode).await;
    let len = human_len(entry);
    format!("@{author}: {key} = {content} ({len})")
}

/// Format the first 5 bytes of a byte string in bas32
pub fn fmt_short(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&hash.as_ref()[..5]);
    text.make_ascii_lowercase();
    format!("{}…", &text)
}

fn canonicalize_path(path: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(shellexpand::tilde(&path).to_string());
    Ok(path)
}

fn tag_from_file_name(path: &Path) -> anyhow::Result<Tag> {
    match path.file_name() {
        Some(name) => name
            .to_os_string()
            .into_string()
            .map(|t| t.into())
            .map_err(|e| anyhow!("{e:?} contains invalid Unicode")),
        None => bail!("the given `path` does not have a proper directory or file name"),
    }
}

/// Takes the [`BlobsClient::add_from_path`] and coordinates adding blobs to a
/// document via the hash of the blob.
/// It also creates and powers the [`ImportProgressBar`].
#[tracing::instrument(skip_all)]
async fn import_coordinator(
    doc: Doc,
    author_id: AuthorId,
    root: PathBuf,
    prefix: String,
    blob_add_progress: impl Stream<Item = Result<AddProgress>> + Send + Unpin + 'static,
    expected_size: u64,
    expected_entries: u64,
) -> Result<()> {
    let imp = ImportProgressBar::new(
        &root.display().to_string(),
        doc.id(),
        expected_size,
        expected_entries,
    );
    let task_imp = imp.clone();

    let collections = Rc::new(RefCell::new(BTreeMap::<
        u64,
        (String, u64, Option<Hash>, u64),
    >::new()));

    let _stats: Vec<u64> = blob_add_progress
        .filter_map(|item| async {
            let item = match item.context("Error adding files") {
                Err(e) => return Some(Err(e)),
                Ok(item) => item,
            };
            match item {
                AddProgress::Found { name, id, size } => {
                    tracing::info!("Found({id},{name},{size})");
                    imp.add_found(name.clone(), size);
                    collections.borrow_mut().insert(id, (name, size, None, 0));
                    None
                }
                AddProgress::Progress { id, offset } => {
                    tracing::info!("Progress({id}, {offset})");
                    if let Some((_, size, _, last_val)) = collections.borrow_mut().get_mut(&id) {
                        assert!(*last_val <= offset, "wtf");
                        assert!(offset <= *size, "wtf2");
                        imp.add_progress(offset - *last_val);
                        *last_val = offset;
                    }
                    None
                }
                AddProgress::Done { hash, id } => {
                    tracing::info!("Done({id},{hash:?})");
                    match collections.borrow_mut().get_mut(&id) {
                        Some((path_str, size, ref mut h, last_val)) => {
                            imp.add_progress(*size - *last_val);
                            imp.import_found(path_str.clone());
                            *h = Some(hash);
                            let key = match key_from_path_str(
                                root.clone(),
                                prefix.clone(),
                                path_str.clone(),
                            ) {
                                Ok(k) => k,
                                Err(e) => {
                                    tracing::info!("error getting key from {}, id {id}", path_str);
                                    return Some(Err(anyhow::anyhow!(
                                        "Issue creating a key for entry {hash:?}: {e}"
                                    )));
                                }
                            };
                            // send update to doc
                            tracing::info!(
                                "setting entry {} (id: {id}) to doc",
                                String::from_utf8(key.clone()).unwrap()
                            );
                            Some(Ok((key, hash, *size)))
                        }
                        None => {
                            tracing::info!(
                                "error: got `AddProgress::Done` for unknown collection id {id}"
                            );
                            Some(Err(anyhow::anyhow!(
                                "Received progress information on an unknown file."
                            )))
                        }
                    }
                }
                AddProgress::AllDone { hash, .. } => {
                    imp.add_done();
                    tracing::info!("AddProgress::AllDone({hash:?})");
                    None
                }
                AddProgress::Abort(e) => {
                    tracing::info!("Error while adding data: {e}");
                    Some(Err(anyhow::anyhow!("Error while adding files: {e}")))
                }
            }
        })
        .try_chunks(1024)
        .map_ok(|chunks| {
            futures::stream::iter(chunks.into_iter().map(|(key, hash, size)| {
                let doc = doc.clone();
                let imp = task_imp.clone();
                Ok(async move {
                    doc.set_hash(author_id, key, hash, size).await?;
                    imp.import_progress();
                    anyhow::Ok(size)
                })
            }))
        })
        .try_flatten()
        .try_buffer_unordered(64)
        .try_collect()
        .await?;

    task_imp.all_done();
    Ok(())
}

/// Creates a document key from the path, removing the full canonicalized path, and adding
/// whatever prefix the user requests.
fn key_from_path_str(root: PathBuf, prefix: String, path_str: String) -> Result<Vec<u8>> {
    let suffix = PathBuf::from(path_str)
        .strip_prefix(root)?
        .to_str()
        .map(|p| p.as_bytes())
        .ok_or(anyhow!("could not convert path to bytes"))?
        .to_vec();
    let mut key = prefix.into_bytes().to_vec();
    key.extend(suffix);
    Ok(key)
}

#[derive(Debug, Clone)]
struct ImportProgressBar {
    mp: MultiProgress,
    import: ProgressBar,
    add: ProgressBar,
}

impl ImportProgressBar {
    fn new(source: &str, doc_id: NamespaceId, expected_size: u64, expected_entries: u64) -> Self {
        let mp = MultiProgress::new();
        let add = mp.add(ProgressBar::new(0));
        add.set_style(ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})").unwrap()
            .progress_chars("=>-"));
        add.set_message(format!("Importing from {source}..."));
        add.set_length(expected_size);
        add.set_position(0);
        add.enable_steady_tick(Duration::from_millis(500));

        let doc_id = fmt_short(doc_id.to_bytes());
        let import = mp.add(ProgressBar::new(0));
        import.set_style(ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, eta {eta})").unwrap()
            .progress_chars("=>-"));
        import.set_message(format!("Adding to doc {doc_id}..."));
        import.set_length(expected_entries);
        import.set_position(0);
        import.enable_steady_tick(Duration::from_millis(500));

        Self { mp, import, add }
    }

    fn add_found(&self, _name: String, _size: u64) {}

    fn import_found(&self, _name: String) {}

    fn add_progress(&self, size: u64) {
        self.add.inc(size);
    }

    fn import_progress(&self) {
        self.import.inc(1);
    }

    fn add_done(&self) {
        self.add.set_position(self.add.length().unwrap_or_default());
    }

    fn all_done(self) {
        self.mp.clear().ok();
    }
}
