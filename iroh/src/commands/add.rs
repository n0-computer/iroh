use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use futures::{Stream, StreamExt};
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use iroh::{
    client::Iroh,
    rpc_protocol::{ProviderService, SetTagOption, WrapOption},
    ticket::blob::Ticket,
};
use iroh_bytes::{
    protocol::RequestToken, provider::AddProgress, util::Tag, BlobFormat, Hash, HashAndFormat,
};
use quic_rpc::ServiceConnection;
use tokio::io::AsyncWriteExt;

use super::BlobAddOptions;

/// Data source for adding data to iroh.
#[derive(Debug, Clone)]
pub enum BlobSource {
    /// A file or directory on the node's local file system.
    LocalFs { path: PathBuf, in_place: bool },
    /// Data passed via STDIN.
    Stdin,
}

/// Whether to print an all-in-one ticket.
#[derive(Debug, Clone)]
pub enum TicketOption {
    /// Do not print an all-in-one ticket
    None,
    /// Print an all-in-one ticket. Optionally include a request token in the ticket.
    Print(Option<RequestToken>),
}

pub async fn run_with_opts<C: ServiceConnection<ProviderService>>(
    client: &Iroh<C>,
    opts: BlobAddOptions,
    request_token: Option<RequestToken>,
) -> Result<()> {
    let tag = match opts.tag {
        Some(tag) => SetTagOption::Named(Tag::from(tag)),
        None => SetTagOption::Auto,
    };
    let ticket = match opts.no_ticket {
        true => TicketOption::None,
        false => TicketOption::Print(request_token),
    };
    let source = match opts.source {
        None => {
            // Nothing to do
            return Ok(());
        }
        Some(super::BlobSource::Stdin) => BlobSource::Stdin,
        Some(super::BlobSource::Path(path)) => BlobSource::LocalFs {
            path,
            in_place: opts.in_place,
        },
    };
    let wrap = match (opts.wrap, opts.filename) {
        (true, None) => WrapOption::Wrap { name: None },
        (true, Some(filename)) => WrapOption::Wrap {
            name: Some(filename),
        },
        (false, None) => WrapOption::NoWrap,
        (false, Some(_)) => bail!("`--filename` may not be used without `--wrap`"),
    };

    run(client, source, tag, ticket, wrap).await
}

/// Add data to iroh, either from a path or, if path is `None`, from STDIN.
pub async fn run<C: ServiceConnection<ProviderService>>(
    client: &Iroh<C>,
    source: BlobSource,
    tag: SetTagOption,
    ticket: TicketOption,
    wrap: WrapOption,
) -> Result<()> {
    let (hash, format, entries) = match source {
        BlobSource::LocalFs { path, in_place } => {
            let absolute = path.canonicalize()?;
            println!("Adding {} as {}...", path.display(), absolute.display());

            // tell the node to add the data
            let stream = client
                .blobs
                .add_from_path(absolute, in_place, tag, wrap)
                .await?;
            aggregate_add_response(stream).await?
        }
        BlobSource::Stdin => {
            println!("Adding from STDIN...");
            // Store STDIN content into a temporary file
            let (file, path) = tempfile::NamedTempFile::new()?.into_parts();
            let mut file = tokio::fs::File::from_std(file);
            let path_buf = path.to_path_buf();
            // Copy from stdin to the file, until EOF
            tokio::io::copy(&mut tokio::io::stdin(), &mut file).await?;
            file.flush().await?;
            drop(file);

            // tell the node to add the data
            let stream = client
                .blobs
                .add_from_path(path_buf, false, tag, wrap)
                .await?;
            aggregate_add_response(stream).await?
        }
    };

    print_add_response(hash, format, entries);
    if let TicketOption::Print(token) = ticket {
        let status = client.node.status().await?;
        let ticket = Ticket::new(status.addr, hash, format, token)?;
        println!("All-in-one ticket: {ticket}");
    }
    Ok(())
}

#[derive(Debug)]
pub struct ProvideResponseEntry {
    pub name: String,
    pub size: u64,
    pub hash: Hash,
}

pub async fn aggregate_add_response(
    mut stream: impl Stream<Item = Result<AddProgress>> + Unpin,
) -> Result<(Hash, BlobFormat, Vec<ProvideResponseEntry>)> {
    let mut hash_and_format = None;
    let mut collections = BTreeMap::<u64, (String, u64, Option<Hash>)>::new();
    let mut mp = Some(ProvideProgressState::new());
    while let Some(item) = stream.next().await {
        match item? {
            AddProgress::Found { name, id, size } => {
                tracing::trace!("Found({id},{name},{size})");
                if let Some(mp) = mp.as_mut() {
                    mp.found(name.clone(), id, size);
                }
                collections.insert(id, (name, size, None));
            }
            AddProgress::Progress { id, offset } => {
                tracing::trace!("Progress({id}, {offset})");
                if let Some(mp) = mp.as_mut() {
                    mp.progress(id, offset);
                }
            }
            AddProgress::Done { hash, id } => {
                tracing::trace!("Done({id},{hash:?})");
                if let Some(mp) = mp.as_mut() {
                    mp.done(id, hash);
                }
                match collections.get_mut(&id) {
                    Some((_, _, ref mut h)) => {
                        *h = Some(hash);
                    }
                    None => {
                        anyhow::bail!("Got Done for unknown collection id {id}");
                    }
                }
            }
            AddProgress::AllDone { hash, format, .. } => {
                tracing::trace!("AllDone({hash:?})");
                if let Some(mp) = mp.take() {
                    mp.all_done();
                }
                hash_and_format = Some(HashAndFormat { hash, format });
                break;
            }
            AddProgress::Abort(e) => {
                if let Some(mp) = mp.take() {
                    mp.error();
                }
                anyhow::bail!("Error while adding data: {e}");
            }
        }
    }
    let HashAndFormat { hash, format } =
        hash_and_format.context("Missing hash for collection or blob")?;
    let entries = collections
        .into_iter()
        .map(|(_, (name, size, hash))| {
            let hash = hash.context(format!("Missing hash for {name}"))?;
            Ok(ProvideResponseEntry { name, size, hash })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((hash, format, entries))
}

pub fn print_add_response(hash: Hash, format: BlobFormat, entries: Vec<ProvideResponseEntry>) {
    let mut total_size = 0;
    for ProvideResponseEntry { name, size, hash } in entries {
        total_size += size;
        println!("- {}: {} {:#}", name, HumanBytes(size), hash);
    }
    println!("Total: {}", HumanBytes(total_size));
    println!();
    match format {
        BlobFormat::Raw => println!("Blob: {}", hash),
        BlobFormat::HashSeq => println!("Collection: {}", hash),
    }
}

#[derive(Debug)]
pub struct ProvideProgressState {
    mp: MultiProgress,
    pbs: HashMap<u64, ProgressBar>,
}

impl ProvideProgressState {
    fn new() -> Self {
        Self {
            mp: MultiProgress::new(),
            pbs: HashMap::new(),
        }
    }

    fn found(&mut self, name: String, id: u64, size: u64) {
        let pb = self.mp.add(ProgressBar::new(size));
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {msg} {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})").unwrap()
            .progress_chars("=>-"));
        pb.set_message(name);
        pb.set_length(size);
        pb.set_position(0);
        pb.enable_steady_tick(Duration::from_millis(500));
        self.pbs.insert(id, pb);
    }

    fn progress(&mut self, id: u64, progress: u64) {
        if let Some(pb) = self.pbs.get_mut(&id) {
            pb.set_position(progress);
        }
    }

    fn done(&mut self, id: u64, _hash: Hash) {
        if let Some(pb) = self.pbs.remove(&id) {
            pb.finish_and_clear();
            self.mp.remove(&pb);
        }
    }

    fn all_done(self) {
        self.mp.clear().ok();
    }

    fn error(self) {
        self.mp.clear().ok();
    }
}
