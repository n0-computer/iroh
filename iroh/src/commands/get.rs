use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use console::style;
use futures::StreamExt;
use indicatif::{
    HumanBytes, HumanDuration, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle,
};
use iroh::{
    collection::{Collection, IrohCollectionParser},
    rpc_protocol::{BlobDownloadRequest, DownloadLocation},
    util::{io::pathbuf_from_name, progress::ProgressSliceWriter},
};
use iroh_bytes::{baomap::range_collections::RangeSet2, provider::GetProgress, util::SetTagOption};
use iroh_bytes::{
    get::{
        self,
        fsm::{self, ConnectedNext, EndBlobNext},
    },
    protocol::{GetRequest, RangeSpecSeq, Request, RequestToken},
    Hash,
};
use iroh_io::ConcatenateSliceWriter;
use tokio::sync::mpsc;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub struct GetInteractive {
    pub rt: iroh_bytes::util::runtime::Handle,
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

    /// Get into a file or directory
    async fn get_to_dir(self, mut out_dir: PathBuf) -> Result<()> {
        if !out_dir.is_absolute() {
            out_dir = std::env::current_dir()?.join(out_dir);
        }
        let parent = out_dir.parent().context("out_dir should have parent")?;
        let temp_dir = parent.join(".iroh-tmp");
        tracing::info!(
            "using temp dir: {} for storing resume data",
            temp_dir.display()
        );
        if tokio::fs::try_exists(&temp_dir).await? {
            let temp_dir_meta = tokio::fs::metadata(&temp_dir).await?;
            if !temp_dir_meta.is_dir() {
                anyhow::bail!(
                    "temp dir: {} exists, but is not a directory",
                    temp_dir.display()
                );
            }
        }
        tokio::fs::create_dir_all(&temp_dir).await?;
        let db: iroh::baomap::flat::Store =
            iroh::baomap::flat::Store::load(&temp_dir, &temp_dir, &temp_dir, &self.rt).await?;
        // TODO: we don't need sync here, maybe disable completely?
        let doc_store = iroh_sync::store::memory::Store::default();
        // spin up temp node and ask it to download the data for us
        let mut provider =
            iroh::node::Node::builder(db, doc_store).collection_parser(IrohCollectionParser);
        if let Some(ref dm) = self.opts.derp_map {
            provider = provider.enable_derp(dm.clone());
        }
        let provider = provider
            .runtime(&iroh_bytes::util::runtime::Handle::from_current(1)?)
            .spawn()
            .await?;
        let out = out_dir
            .to_str()
            .context("out_dir is not valid utf8")?
            .to_owned();
        let hash = self.hash;
        write(format!("Fetching: {}", hash));
        write(format!("{} Connecting ...", style("[1/3]").bold().dim()));
        let mut stream = provider
            .client()
            .blobs
            .download(BlobDownloadRequest {
                hash: self.hash,
                recursive: !self.single,
                peer: self.opts.peer,
                token: self.token,
                out: DownloadLocation::External {
                    path: out,
                    in_place: true,
                },
                tag: SetTagOption::Auto,
            })
            .await?;
        let pb = make_download_pb();
        let mut sizes = BTreeMap::new();
        while let Some(x) = stream.next().await {
            match x? {
                GetProgress::Connected => {
                    write(format!("{} Requesting ...", style("[2/3]").bold().dim()));
                }
                GetProgress::FoundCollection {
                    total_blobs_size,
                    num_blobs,
                    ..
                } => {
                    init_download_progress(
                        &pb,
                        num_blobs.unwrap_or_default(),
                        total_blobs_size.unwrap_or_default(),
                    )?;
                }
                GetProgress::Found { id, size, .. } => {
                    sizes.insert(id, (size, 0));
                }
                GetProgress::Progress { id, offset } => {
                    if let Some((_, current)) = sizes.get_mut(&id) {
                        *current = offset;
                        let total = sizes.values().map(|(_, current)| current).sum::<u64>();
                        pb.set_position(total);
                    }
                }
                GetProgress::Done { id } => {
                    if let Some((size, current)) = sizes.get_mut(&id) {
                        *current = *size;
                        let total = sizes.values().map(|(_, current)| current).sum::<u64>();
                        pb.set_position(total);
                    }
                }
                GetProgress::NetworkDone {
                    bytes_read,
                    elapsed,
                    ..
                } => {
                    pb.finish_and_clear();
                    write(format!(
                        "Transferred {} in {}, {}/s",
                        HumanBytes(bytes_read),
                        HumanDuration(elapsed),
                        HumanBytes((bytes_read as f64 / elapsed.as_secs_f64()) as u64)
                    ));
                }
                GetProgress::AllDone => {
                    break;
                }
                _ => {}
            }
        }
        tokio::fs::remove_dir_all(temp_dir).await?;
        Ok(())
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
            RangeSpecSeq::from_ranges([RangeSet2::all()])
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
    let (next, links) = {
        let curr = curr.next();
        let (curr, data) = curr.concatenate_into_vec().await?;
        let links = postcard::from_bytes::<Box<[Hash]>>(&data)?;
        (curr.next(), links)
    };
    let EndBlobNext::MoreChildren(at_meta) = next else {
        anyhow::bail!("expected meta");
    };
    let (mut next, collection) = {
        let curr = at_meta.next(links[0]);
        let (curr, names) = curr.concatenate_into_vec().await?;
        let names = postcard::from_bytes::<Box<[String]>>(&names)?;
        let collection = Collection::from_parts(&links[1..], &names)?;
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
        let blob = match collection.get(child_offset - 1) {
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
