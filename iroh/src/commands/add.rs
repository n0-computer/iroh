use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use iroh::client::quic::Iroh;
use iroh_bytes::{provider::AddProgress, Hash};

pub async fn run(iroh: &Iroh, path: PathBuf, in_place: bool, tag: Option<Bytes>) -> Result<()> {
    let absolute = path.canonicalize()?;
    println!("Adding {} as {}...", path.display(), absolute.display());
    let stream = iroh.blobs.add_from_path(absolute, in_place, tag).await?;
    let (hash, entries) = aggregate_add_response(stream).await?;
    print_add_response(hash, entries);
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
