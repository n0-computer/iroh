use std::path::PathBuf;

use anyhow::{Context as _, Result};
use bao_tree::ChunkRanges;
use futures::StreamExt;
use iroh::{
    collection::Collection,
    rpc_protocol::{BlobDownloadRequest, DownloadLocation, SetTagOption},
    util::progress::ProgressSliceWriter,
};
use iroh_bytes::{
    get::{
        self,
        fsm::{self, ConnectedNext, EndBlobNext},
    },
    protocol::{GetRequest, RangeSpecSeq, RequestToken},
    Hash,
};
use iroh_bytes::{
    provider::DownloadProgress,
    util::{
        progress::{FlumeProgressSender, IdGenerator, ProgressSender},
        BlobFormat,
    },
};
use iroh_io::ConcatenateSliceWriter;
use iroh_net::derp::DerpMode;

use crate::commands::show_download_progress;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub struct GetInteractive {
    pub rt: iroh_bytes::util::runtime::Handle,
    pub hash: Hash,
    pub format: BlobFormat,
    pub opts: iroh::dial::Options,
    pub token: Option<RequestToken>,
}

impl GetInteractive {
    fn new_request(&self, query: RangeSpecSeq) -> GetRequest {
        GetRequest::new(self.hash, query).with_token(self.token.clone())
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
        let db =
            iroh_bytes::store::flat::Store::load(&temp_dir, &temp_dir, &temp_dir, &self.rt).await?;
        // TODO: we don't need sync here, maybe disable completely?
        let doc_store = iroh_sync::store::memory::Store::default();
        // spin up temp node and ask it to download the data for us
        let mut provider = iroh::node::Node::builder(db, doc_store);
        if let Some(ref dm) = self.opts.derp_map {
            provider = provider.derp_mode(DerpMode::Custom(dm.clone()));
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
        let stream = provider
            .client()
            .blobs
            .download(BlobDownloadRequest {
                hash: self.hash,
                format: self.format,
                peer: self.opts.peer,
                token: self.token,
                out: DownloadLocation::External {
                    path: out,
                    in_place: true,
                },
                tag: SetTagOption::Auto,
            })
            .await?;
        show_download_progress(hash, stream).await?;
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
        let hash = self.hash;
        let (sender, receiver) = flume::bounded(1024);
        let sender = FlumeProgressSender::new(sender);
        let display_task =
            tokio::task::spawn(show_download_progress(hash, receiver.into_stream().map(Ok)));
        let query = if self.format.is_raw() {
            // just get the entire first item
            RangeSpecSeq::from_ranges([ChunkRanges::all()])
        } else {
            // get everything (collection and children)
            RangeSpecSeq::all()
        };

        let request = self.new_request(query).with_token(self.token.clone());
        let connection = iroh::dial::dial(self.opts).await?;
        let response = fsm::start(connection, request);
        let connected = response.next().await?;
        // we are connected
        sender.send(DownloadProgress::Connected).await?;
        let ConnectedNext::StartRoot(curr) = connected.next().await? else {
            anyhow::bail!("expected root to be present");
        };
        let stats = if self.format.is_raw() {
            get_to_stdout_single(curr, sender.clone()).await?
        } else {
            get_to_stdout_multi(curr, sender.clone()).await?
        };
        sender
            .send(DownloadProgress::NetworkDone {
                bytes_written: stats.bytes_written,
                bytes_read: stats.bytes_read,
                elapsed: stats.elapsed,
            })
            .await?;
        sender.send(DownloadProgress::AllDone).await?;
        display_task.await??;

        Ok(())
    }
}

async fn get_to_stdout_single(
    curr: get::fsm::AtStartRoot,
    sender: FlumeProgressSender<DownloadProgress>,
) -> Result<get::Stats> {
    let curr = curr.next();
    let id = sender.new_id();
    let hash = curr.hash();
    let (curr, size) = curr.next().await?;
    sender
        .send(DownloadProgress::Found {
            id,
            hash,
            size,
            child: 0,
        })
        .await?;
    let sender2 = sender.clone();
    let mut writer = ProgressSliceWriter::new(
        ConcatenateSliceWriter::new(tokio::io::stdout()),
        move |offset| {
            sender2.try_send(DownloadProgress::Progress { id, offset }).ok();
        },
    );
    let curr = curr.write_all(&mut writer).await?;
    sender.send(DownloadProgress::Done { id }).await?;
    let EndBlobNext::Closing(curr) = curr.next() else {
        anyhow::bail!("expected end of stream")
    };
    Ok(curr.next().await?)
}

async fn get_to_stdout_multi(
    curr: get::fsm::AtStartRoot,
    sender: FlumeProgressSender<DownloadProgress>,
) -> Result<get::Stats> {
    let hash = curr.hash();
    let (mut next, links, collection) = Collection::read_fsm(curr).await?;
    sender
        .send(DownloadProgress::FoundHashSeq {
            hash,
            children: links.len() as u64,
        })
        .await?;
    let collection = collection.into_inner();
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
        let header = start.next(blob.hash);
        // create task that updates the progress bar
        let id = sender.new_id();
        let (curr, size) = header.next().await?;
        sender
            .send(DownloadProgress::Found {
                id,
                hash: blob.hash,
                size,
                child: curr.offset(),
            })
            .await?;
        let sender2 = sender.clone();
        let mut io_writer = ProgressSliceWriter::new(
            ConcatenateSliceWriter::new(tokio::io::stdout()),
            move |offset| {
                sender2.try_send(DownloadProgress::Progress { id, offset }).ok();
            },
        );
        let curr = curr.write_all(&mut io_writer).await?;
        sender.send(DownloadProgress::Done { id }).await?;
        // wait for the progress task to finish, only after dropping the writer
        next = curr.next();
    };
    Ok(finishing.next().await?)
}
