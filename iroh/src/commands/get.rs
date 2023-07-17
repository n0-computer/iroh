use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use bao_tree::{io::outboard::PreOrderMemOutboard, ByteNum, ChunkNum};
use console::style;
use indicatif::{
    HumanBytes, HumanDuration, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle,
};
use iroh::{
    collection::Collection,
    util::{io::pathbuf_from_name, progress::ProgressSliceWriter},
};
use iroh_bytes::{
    get::{
        self,
        fsm::{self, ConnectedNext, EndBlobNext},
    },
    protocol::{GetRequest, RangeSpecSeq, Request, RequestToken},
    Hash,
};
use iroh_io::{AsyncSliceWriter, ConcatenateSliceWriter, File};
use range_collections::RangeSet2;
use tokio::sync::mpsc;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub struct GetInteractive {
    pub hash: Hash,
    pub opts: iroh::dial::Options,
    pub token: Option<RequestToken>,
    pub single: bool,
}

/// Write the given data.
pub fn write(data: impl AsRef<str>) {
    eprintln!("{}", data.as_ref());
}

impl GetInteractive {
    fn new_request(&self, query: RangeSpecSeq) -> Request {
        GetRequest::new(self.hash, query)
            .with_token(self.token.clone())
            .into()
    }

    /// Get a single file.
    async fn get_to_file_single(self, out_dir: PathBuf, temp_dir: PathBuf) -> Result<()> {
        let hash = self.hash;
        write(format!("Fetching: {}", hash));
        write(format!("{} Connecting ...", style("[1/3]").bold().dim()));

        let name = hash.to_string();
        // range I am missing for the 1 file I am downloading
        let range = get_missing_range(&self.hash, name.as_str(), &temp_dir, &out_dir)?;
        if range.is_all() {
            tokio::fs::create_dir_all(&temp_dir)
                .await
                .context("unable to create directory {temp_dir}")?;
            tokio::fs::create_dir_all(&out_dir)
                .await
                .context("Unable to create directory {out_dir}")?;
        }
        let query = RangeSpecSeq::new([range]);
        let pb = make_download_pb();

        // collection info, in case we won't get a callback with is_root
        let collection_info = Some((1, 0));

        let request = self.new_request(query).with_token(self.token.clone());
        let connection = iroh::dial::dial(self.opts).await?;
        let response = fsm::start(connection, request);
        let connected = response.next().await?;
        write(format!("{} Requesting ...", style("[2/3]").bold().dim()));
        if let Some((count, missing_bytes)) = collection_info {
            init_download_progress(&pb, count, missing_bytes)?;
        }
        let ConnectedNext::StartRoot(curr) = connected.next().await? else {
            anyhow::bail!("Unexpected StartChild or Closing");
        };
        let header = curr.next();
        let final_path = out_dir.join(&name);
        let tempname = hash.to_hex();
        let data_path = temp_dir.join(format!("{tempname}.data.part"));
        let outboard_path = temp_dir.join(format!("{tempname}.outboard.part"));
        let data_path_2 = data_path.clone();
        let mut data_file = File::create(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&data_path_2)
        })
        .await?;
        tracing::debug!("piping data to {:?} and {:?}", data_path, outboard_path);
        let (curr, size) = header.next().await?;
        pb.set_length(size);
        let mut outboard_file = if size > 0 {
            let outboard_path = outboard_path.clone();
            let outboard_file = File::create(move || {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&outboard_path)
            })
            .await?;
            Some(outboard_file)
        } else {
            None
        };
        let curr = curr
            .write_all_with_outboard(outboard_file.as_mut(), &mut data_file)
            .await?;
        // Flush the data file first, it is the only thing that matters at this point
        data_file.sync().await?;
        drop(data_file);
        // Rename temp file, to target name
        // once this is done, the file is considered complete
        tokio::fs::rename(data_path, final_path).await?;
        if let Some(mut outboard_file) = outboard_file.take() {
            // not sure if we have to do this
            outboard_file.sync().await?;
            // delete the outboard file
            tokio::fs::remove_file(outboard_path).await?;
        }
        let EndBlobNext::Closing(finishing) = curr.next() else {
            anyhow::bail!("Unexpected StartChild or MoreChildren");
        };
        let stats = finishing.next().await?;
        tokio::fs::remove_dir_all(temp_dir).await?;
        pb.finish_and_clear();
        write(format!(
            "Transferred {} in {}, {}/s",
            HumanBytes(stats.bytes_read),
            HumanDuration(stats.elapsed),
            HumanBytes((stats.bytes_read as f64 / stats.elapsed.as_secs_f64()) as u64)
        ));

        Ok(())
    }

    /// Get into a file or directory
    async fn get_to_dir_multi(self, out_dir: PathBuf, temp_dir: PathBuf) -> Result<()> {
        let hash = self.hash;
        write(format!("Fetching: {}", hash));
        write(format!("{} Connecting ...", style("[1/3]").bold().dim()));
        let (query, collection) = get_missing_ranges(self.hash, &out_dir, &temp_dir)?;
        let collection = collection.map(|x| x.into_inner()).unwrap_or_default();

        let pb = make_download_pb();

        // collection info, in case we won't get a callback with is_root
        let collection_info = if collection.is_empty() {
            None
        } else {
            Some((collection.len() as u64, 0))
        };

        let request = self.new_request(query).with_token(self.token.clone());
        let connection = iroh::dial::dial(self.opts).await?;
        let response = fsm::start(connection, request);
        let connected = response.next().await?;
        write(format!("{} Requesting ...", style("[2/3]").bold().dim()));
        if let Some((count, missing_bytes)) = collection_info {
            init_download_progress(&pb, count, missing_bytes)?;
        }
        let (mut next, collection) = match connected.next().await? {
            ConnectedNext::StartRoot(curr) => {
                tokio::fs::create_dir_all(&temp_dir)
                    .await
                    .context("unable to create directory {temp_dir}")?;
                tokio::fs::create_dir_all(&out_dir)
                    .await
                    .context("Unable to create directory {out_dir}")?;
                let curr = curr.next();
                let (curr, collection_data) = curr.concatenate_into_vec().await?;
                let collection = Collection::from_bytes(&collection_data)?;
                init_download_progress(
                    &pb,
                    collection.total_entries(),
                    collection.total_blobs_size(),
                )?;
                tokio::fs::write(get_data_path(&temp_dir, hash), collection_data).await?;
                (curr.next(), collection.into_inner())
            }
            ConnectedNext::StartChild(start_child) => {
                (EndBlobNext::MoreChildren(start_child), collection)
            }
            ConnectedNext::Closing(finish) => (EndBlobNext::Closing(finish), collection),
        };
        // read all the children
        let finishing = loop {
            let start = match next {
                EndBlobNext::MoreChildren(sc) => sc,
                EndBlobNext::Closing(finish) => break finish,
            };
            let child_offset = start.child_offset() as usize;
            let blob = match collection.get(child_offset) {
                Some(blob) => blob,
                None => break start.finish(),
            };

            let hash = blob.hash;
            let name = &blob.name;
            let name = if name.is_empty() {
                PathBuf::from(hash.to_string())
            } else {
                pathbuf_from_name(name)
            };
            pb.set_message(format!("Receiving '{}'...", name.display()));
            pb.reset();
            let header = start.next(blob.hash);

            let curr = {
                let final_path = out_dir.join(&name);
                let tempname = hash.to_hex();
                let data_path = temp_dir.join(format!("{tempname}.data.part"));
                let outboard_path = temp_dir.join(format!("{tempname}.outboard.part"));
                let data_path_2 = data_path.clone();
                let data_file = File::create(move || {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .open(&data_path_2)
                })
                .await?;
                tracing::debug!("piping data to {data_path:?} and {outboard_path:?}");
                let (curr, size) = header.next().await?;
                pb.set_length(size);
                let mut outboard_file = if size > 0 {
                    let outboard_path = outboard_path.clone();
                    let outboard_file = File::create(move || {
                        std::fs::OpenOptions::new()
                            .write(true)
                            .create(true)
                            .open(&outboard_path)
                    })
                    .await?;
                    Some(outboard_file)
                } else {
                    None
                };

                let (on_write, mut receive_on_write) = mpsc::channel(1);
                let pb2 = pb.clone();
                // create task that updates the progress bar
                let progress_task = tokio::task::spawn(async move {
                    while let Some((offset, _)) = receive_on_write.recv().await {
                        pb2.set_position(offset);
                    }
                });
                let mut data_file = ProgressSliceWriter::new(data_file, on_write);
                let curr = curr
                    .write_all_with_outboard(outboard_file.as_mut(), &mut data_file)
                    .await?;
                // Flush the data file first, it is the only thing that matters at this point
                data_file.sync().await?;
                drop(data_file);

                // wait for the progress task to finish, only after dropping the ProgressSliceWriter
                progress_task.await.ok();
                tokio::fs::create_dir_all(
                    final_path
                        .parent()
                        .context("final path should have parent")?,
                )
                .await?;
                // Rename temp file, to target name
                // once this is done, the file is considered complete
                tokio::fs::rename(data_path, final_path).await?;
                if let Some(mut outboard_file) = outboard_file.take() {
                    // not sure if we have to do this
                    outboard_file.sync().await?;
                    // delete the outboard file
                    tokio::fs::remove_file(outboard_path).await?;
                }
                curr
            };
            pb.finish();
            next = curr.next();
        };
        let stats = finishing.next().await?;
        tokio::fs::remove_dir_all(temp_dir).await?;
        pb.finish_and_clear();
        write(format!(
            "Transferred {} in {}, {}/s",
            HumanBytes(stats.bytes_read),
            HumanDuration(stats.elapsed),
            HumanBytes((stats.bytes_read as f64 / stats.elapsed.as_secs_f64()) as u64)
        ));

        Ok(())
    }

    /// Get into a file or directory
    async fn get_to_dir(self, out_dir: PathBuf) -> Result<()> {
        let temp_dir = out_dir.join(".iroh-tmp");
        if self.single {
            self.get_to_file_single(out_dir, temp_dir).await
        } else {
            self.get_to_dir_multi(out_dir, temp_dir).await
        }
    }

    pub async fn get_interactive(self, out_dir: Option<PathBuf>) -> Result<()> {
        if let Some(out_dir) = out_dir {
            self.get_to_dir(out_dir).await
        } else {
            self.get_to_stdout().await
        }
    }

    /// Get to stdout, no resume possible.
    async fn get_to_stdout(self) -> Result<()> {
        write(format!("Fetching: {}", self.hash));
        write(format!("{} Connecting ...", style("[1/3]").bold().dim()));
        let query = if self.single {
            // just get the entire first item
            RangeSpecSeq::new([RangeSet2::all()])
        } else {
            // get everything (collection and children)
            RangeSpecSeq::all()
        };

        let pb = make_download_pb();
        let request = self.new_request(query).with_token(self.token.clone());
        let connection = iroh::dial::dial(self.opts).await?;
        let response = fsm::start(connection, request);
        let connected = response.next().await?;
        write(format!("{} Requesting ...", style("[2/3]").bold().dim()));
        let ConnectedNext::StartRoot(curr) = connected.next().await? else {
        anyhow::bail!("expected root to be present");
    };
        let stats = if self.single {
            get_to_stdout_single(curr).await?
        } else {
            get_to_stdout_multi(curr, pb.clone()).await?
        };
        pb.finish_and_clear();
        write(format!(
            "Transferred {} in {}, {}/s",
            HumanBytes(stats.bytes_read),
            HumanDuration(stats.elapsed),
            HumanBytes((stats.bytes_read as f64 / stats.elapsed.as_secs_f64()) as u64)
        ));

        Ok(())
    }
}

async fn get_to_stdout_single(curr: get::fsm::AtStartRoot) -> Result<get::Stats> {
    let curr = curr.next();
    let mut writer = ConcatenateSliceWriter::new(tokio::io::stdout());
    let curr = curr.write_all(&mut writer).await?;
    let EndBlobNext::Closing(curr) = curr.next() else {
        anyhow::bail!("expected end of stream")
    };
    Ok(curr.next().await?)
}

async fn get_to_stdout_multi(curr: get::fsm::AtStartRoot, pb: ProgressBar) -> Result<get::Stats> {
    let (mut next, collection) = {
        let curr = curr.next();
        let (curr, collection_data) = curr.concatenate_into_vec().await?;
        let collection = Collection::from_bytes(&collection_data)?;
        let count = collection.total_entries();
        let missing_bytes = collection.total_blobs_size();
        write(format!("{} Downloading ...", style("[3/3]").bold().dim()));
        write(format!(
            "  {} file(s) with total transfer size {}",
            count,
            HumanBytes(missing_bytes)
        ));
        pb.set_length(missing_bytes);
        pb.reset();
        pb.set_draw_target(ProgressDrawTarget::stderr());
        (curr.next(), collection.into_inner())
    };
    // read all the children
    let finishing = loop {
        let start = match next {
            EndBlobNext::MoreChildren(sc) => sc,
            EndBlobNext::Closing(finish) => break finish,
        };
        let child_offset = start.child_offset() as usize;
        let blob = match collection.get(child_offset) {
            Some(blob) => blob,
            None => break start.finish(),
        };

        let hash = blob.hash;
        let name = &blob.name;
        let name = if name.is_empty() {
            PathBuf::from(hash.to_string())
        } else {
            pathbuf_from_name(name)
        };
        pb.set_message(format!("Receiving '{}'...", name.display()));
        pb.reset();
        let header = start.next(blob.hash);
        let (on_write, mut receive_on_write) = mpsc::channel(1);
        let pb2 = pb.clone();
        // create task that updates the progress bar
        let progress_task = tokio::task::spawn(async move {
            while let Some((offset, _)) = receive_on_write.recv().await {
                pb2.set_position(offset);
            }
        });
        let mut io_writer =
            ProgressSliceWriter::new(ConcatenateSliceWriter::new(tokio::io::stdout()), on_write);
        let curr = header.write_all(&mut io_writer).await?;
        drop(io_writer);
        // wait for the progress task to finish, only after dropping the writer
        progress_task.await.ok();
        pb.finish();
        next = curr.next();
    };
    Ok(finishing.next().await?)
}

const PROGRESS_STYLE: &str =
    "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})";

fn make_download_pb() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(50));
    pb.set_style(
        ProgressStyle::with_template(PROGRESS_STYLE)
            .unwrap()
            .with_key(
                "eta",
                |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                },
            )
            .progress_chars("#>-"),
    );
    pb
}

fn init_download_progress(pb: &ProgressBar, count: u64, missing_bytes: u64) -> Result<()> {
    write(format!("{} Downloading ...", style("[3/3]").bold().dim()));
    write(format!(
        "  {} file(s) with total transfer size {}",
        count,
        HumanBytes(missing_bytes)
    ));
    pb.set_length(missing_bytes);
    pb.reset();
    pb.set_draw_target(ProgressDrawTarget::stderr());

    Ok(())
}

/// Get missing range for a single file, given a temp and target directory
///
/// This will check missing ranges from the outboard, but for the data file itself
/// just use the length of the file.
pub fn get_missing_range(
    hash: &Hash,
    name: &str,
    temp_dir: &Path,
    target_dir: &Path,
) -> std::io::Result<RangeSet2<ChunkNum>> {
    if target_dir.exists() && !temp_dir.exists() {
        // target directory exists yet does not contain the temp dir
        // we can not resume a partial download, so we just assume that
        // the user wants to start from scratch
        return Ok(RangeSet2::all());
    }
    let range = get_missing_range_impl(hash, name, temp_dir, target_dir)?;
    Ok(range)
}

/// Get missing range for a single file
fn get_missing_range_impl(
    hash: &Hash,
    name: &str,
    temp_dir: &Path,
    target_dir: &Path,
) -> std::io::Result<RangeSet2<ChunkNum>> {
    let paths = FilePaths::new(hash, name, temp_dir, target_dir);
    Ok(if paths.is_final() {
        tracing::debug!("Found final file: {:?}", paths.target);
        // we assume that the file is correct
        RangeSet2::empty()
    } else if paths.is_incomplete() {
        tracing::debug!("Found incomplete file: {:?}", paths.temp);
        // we got incomplete data
        let outboard = std::fs::read(&paths.outboard)?;
        let outboard: std::result::Result<_, _> =
            PreOrderMemOutboard::new((*hash).into(), iroh_bytes::IROH_BLOCK_SIZE, outboard);
        match outboard {
            Ok(outboard) => {
                // compute set of valid ranges from the outboard and the file
                //
                // We assume that the file is correct and does not contain holes.
                // Otherwise, we would have to rehash the file.
                //
                // Do a quick check of the outboard in case something went wrong when writing.
                let mut valid = bao_tree::io::sync::valid_ranges(&outboard)?;
                let valid_from_file =
                    RangeSet2::from(..ByteNum(paths.temp.metadata()?.len()).full_chunks());
                tracing::debug!("valid_from_file: {:?}", valid_from_file);
                tracing::debug!("valid_from_outboard: {:?}", valid);
                valid &= valid_from_file;
                RangeSet2::all().difference(&valid)
            }
            Err(cause) => {
                tracing::debug!("Outboard damaged, assuming missing {cause:?}");
                // the outboard is invalid, so we assume that the file is missing
                RangeSet2::all()
            }
        }
    } else {
        tracing::debug!("Found missing file: {:?}", paths.target);
        // we don't know anything about this file, so we assume it's missing
        RangeSet2::all()
    })
}

/// Given a target directory and a temp directory, get a set of ranges that we are missing
///
/// Assumes that the temp directory contains at least the data for the collection.
/// Also assumes that partial data files do not contain gaps.
pub fn get_missing_ranges(
    hash: Hash,
    target_dir: &Path,
    temp_dir: &Path,
) -> std::io::Result<(RangeSpecSeq, Option<Collection>)> {
    if target_dir.exists() && !temp_dir.exists() {
        // the target directory exists, but does not contain the temp directory
        // that would allow us to resume a partial download, so we just assume that
        // the user wants to start from scratch
        return Ok((RangeSpecSeq::all(), None));
    }
    // try to load the collection from the temp directory
    //
    // if the collection can not be deserialized, we treat it as if it does not exist
    let collection = load_collection(temp_dir, hash).ok().flatten();
    let collection = match collection {
        Some(collection) => collection,
        None => return Ok((RangeSpecSeq::all(), None)),
    };
    let mut ranges = collection
        .blobs()
        .iter()
        .map(|blob| get_missing_range_impl(&blob.hash, blob.name.as_str(), temp_dir, target_dir))
        .collect::<std::io::Result<Vec<_>>>()?;
    ranges
        .iter()
        .zip(collection.blobs())
        .for_each(|(ranges, blob)| {
            if ranges.is_empty() {
                tracing::debug!("{} is complete", blob.name);
            } else if ranges.is_all() {
                tracing::debug!("{} is missing", blob.name);
            } else {
                tracing::debug!("{} is partial {:?}", blob.name, ranges);
            }
        });
    // make room for the collection at offset 0
    // if we get here, we already have the collection, so we don't need to ask for it again.
    ranges.insert(0, RangeSet2::empty());
    Ok((RangeSpecSeq::new(ranges), Some(collection)))
}

#[derive(Debug)]
struct FilePaths {
    target: PathBuf,
    temp: PathBuf,
    outboard: PathBuf,
}

impl FilePaths {
    fn new(hash: &Hash, name: &str, temp_dir: &Path, target_dir: &Path) -> Self {
        let target = target_dir.join(pathbuf_from_name(name));
        let hash = blake3::Hash::from(*hash).to_hex();
        let temp = temp_dir.join(format!("{hash}.data.part"));
        let outboard = temp_dir.join(format!("{hash}.outboard.part"));
        Self {
            target,
            temp,
            outboard,
        }
    }

    fn is_final(&self) -> bool {
        self.target.exists()
    }

    fn is_incomplete(&self) -> bool {
        self.temp.exists() && self.outboard.exists()
    }
}

/// get data path for a hash
pub fn get_data_path(data_path: &Path, hash: Hash) -> PathBuf {
    let hash = blake3::Hash::from(hash).to_hex();
    data_path.join(format!("{hash}.data"))
}

/// Load a collection from a data path
fn load_collection(data_path: &Path, hash: Hash) -> anyhow::Result<Option<Collection>> {
    let collection_path = get_data_path(data_path, hash);
    Ok(if collection_path.exists() {
        let collection = std::fs::read(&collection_path)?;
        let collection = Collection::from_bytes(&collection)?;
        Some(collection)
    } else {
        None
    })
}
