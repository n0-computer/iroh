use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result};
use futures::{Stream, StreamExt};
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use iroh::{client::Iroh, dial::Ticket, rpc_protocol::ProviderService};
use iroh_bytes::{protocol::RequestToken, provider::AddProgress, util::SetTagOption, Hash};
use quic_rpc::ServiceConnection;

/// Add data to iroh, either from a path or, if path is `None`, from STDIN.
pub async fn add_stdin_or_path<C: ServiceConnection<ProviderService>>(
    client: &Iroh<C>,
    path: Option<PathBuf>,
    tag: SetTagOption,
    in_place: bool,
    ticket: bool,
    token_for_ticket: Option<RequestToken>,
) -> Result<()> {
    let (path, _tmp_path) = if let Some(path) = path {
        let absolute = path.canonicalize()?;
        println!("Adding {} as {}...", path.display(), absolute.display());
        (absolute, None)
    } else {
        // Store STDIN content into a temporary file
        let (file, path) = tempfile::NamedTempFile::new()?.into_parts();
        let mut file = tokio::fs::File::from_std(file);
        let path_buf = path.to_path_buf();
        // Copy from stdin to the file, until EOF
        tokio::io::copy(&mut tokio::io::stdin(), &mut file).await?;
        println!("Adding from stdin...");
        // return the TempPath to keep it alive
        (path_buf, Some(path))
    };

    // tell the node to add the data
    let stream = client.blobs.add_from_path(path, in_place, tag).await?;
    let (hash, entries) = aggregate_add_response(stream).await?;
    print_add_response(hash, entries);
    if ticket {
        let status = client.node.status().await?;
        let ticket = Ticket::new(status.addr, hash, token_for_ticket, true)?;
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
) -> Result<(Hash, Vec<ProvideResponseEntry>)> {
    let mut collection_hash = None;
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
            AddProgress::AllDone { hash } => {
                tracing::trace!("AllDone({hash:?})");
                if let Some(mp) = mp.take() {
                    mp.all_done();
                }
                collection_hash = Some(hash);
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
    let hash = collection_hash.context("Missing hash for collection")?;
    let entries = collections
        .into_iter()
        .map(|(_, (name, size, hash))| {
            let hash = hash.context(format!("Missing hash for {name}"))?;
            Ok(ProvideResponseEntry { name, size, hash })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((hash, entries))
}

pub fn print_add_response(hash: Hash, entries: Vec<ProvideResponseEntry>) {
    let mut total_size = 0;
    for ProvideResponseEntry { name, size, hash } in entries {
        total_size += size;
        println!("- {}: {} {:#}", name, HumanBytes(size), hash);
    }
    println!("Total: {}", HumanBytes(total_size));
    println!();
    println!("Collection: {}", hash);
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
