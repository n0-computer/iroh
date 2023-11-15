use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context as _, Result};
use bao_tree::ChunkRanges;
use clap::Parser;
use futures::StreamExt;
use iroh::ticket::blob::Ticket;
use iroh::{
    collection::Collection,
    rpc_protocol::{BlobDownloadRequest, DownloadLocation, SetTagOption},
    util::progress::ProgressSliceWriter,
};
use iroh_bytes::util::runtime;
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
    util::progress::{FlumeProgressSender, IdGenerator, ProgressSender},
    BlobFormat,
};
use iroh_io::ConcatenateSliceWriter;
use iroh_net::derp::DerpMode;
use iroh_net::key::{PublicKey, SecretKey};
use iroh_net::NodeAddr;

use crate::commands::show_download_progress;
use crate::config::NodeConfig;

#[derive(Debug, Clone, Parser)]
pub struct GetArgs {
    /// The hash to retrieve, as a Blake3 CID
    #[clap(conflicts_with = "ticket", required_unless_present = "ticket")]
    hash: Option<Hash>,
    /// PublicKey of the provider
    #[clap(
        long,
        short,
        conflicts_with = "ticket",
        required_unless_present = "ticket"
    )]
    peer: Option<PublicKey>,
    /// Addresses of the provider
    #[clap(long, short)]
    addrs: Vec<SocketAddr>,
    /// base32-encoded Request token to use for authentication, if any
    #[clap(long)]
    token: Option<RequestToken>,
    /// DERP region of the provider
    #[clap(long)]
    region: Option<u16>,
    /// Directory in which to save the file(s). When passed `STDOUT` will be written to stdout,
    /// otherwise the content will be stored in the provided path.
    ///
    /// If the directory exists and contains a partial download, the download will
    /// be resumed.
    ///
    /// Otherwise, all files in the collection will be overwritten. Other files
    /// in the directory will be left untouched.
    #[clap(long, short)]
    out: OutputTarget,
    #[clap(conflicts_with_all = &["hash", "peer", "addrs", "token"])]
    /// Ticket containing everything to retrieve the data from a provider.
    #[clap(long)]
    ticket: Option<Ticket>,
    /// If set assume that the hash refers to a collection and download it with all children.
    #[clap(long, default_value_t = false)]
    collection: bool,
}

/// Where the data should be stored.
#[derive(Debug, Clone, derive_more::Display, PartialEq, Eq)]
pub enum OutputTarget {
    /// Writes to stdout
    #[display("STDOUT")]
    Stdout,
    /// Writes to the provided path
    #[display("{}", _0.display())]
    Path(PathBuf),
}

impl From<String> for OutputTarget {
    fn from(s: String) -> Self {
        if s == "STDOUT" {
            return OutputTarget::Stdout;
        }

        OutputTarget::Path(s.into())
    }
}

impl GetArgs {
    pub async fn run(self, config: &NodeConfig, rt: &runtime::Handle, keylog: bool) -> Result<()> {
        let GetArgs {
            hash,
            peer,
            addrs,
            token,
            region,
            out,
            ticket,
            collection,
        } = self;
        let get = if let Some(ticket) = ticket {
            GetInteractive {
                rt: rt.clone(),
                hash: ticket.hash(),
                opts: ticket.as_get_options(SecretKey::generate(), config.derp_map()?),
                token: ticket.token().cloned(),
                format: ticket.format(),
            }
        } else if let (Some(peer), Some(hash)) = (peer, hash) {
            let format = match collection {
                true => BlobFormat::HashSeq,
                false => BlobFormat::Raw,
            };
            GetInteractive {
                rt: rt.clone(),
                hash,
                opts: iroh::dial::Options {
                    peer: NodeAddr::from_parts(peer, region, addrs),
                    keylog,
                    derp_map: config.derp_map()?,
                    secret_key: SecretKey::generate(),
                },
                token,
                format,
            }
        } else {
            anyhow::bail!("Either ticket or hash and peer must be specified")
        };
        tokio::select! {
            biased;
            res = get.get_interactive(out) => res,
            _ = tokio::signal::ctrl_c() => {
                println!("Ending transfer early...");
                Ok(())
            }
        }
    }
}

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

    pub async fn get_interactive(self, out_dir: OutputTarget) -> Result<()> {
        match out_dir {
            OutputTarget::Path(dir) => self.get_to_dir(dir).await,
            OutputTarget::Stdout => self.get_to_stdout().await,
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
            sender2
                .try_send(DownloadProgress::Progress { id, offset })
                .ok();
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
                sender2
                    .try_send(DownloadProgress::Progress { id, offset })
                    .ok();
            },
        );
        let curr = curr.write_all(&mut io_writer).await?;
        sender.send(DownloadProgress::Done { id }).await?;
        // wait for the progress task to finish, only after dropping the writer
        next = curr.next();
    };
    Ok(finishing.next().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_target() {
        assert_eq!(
            OutputTarget::from(OutputTarget::Stdout.to_string()),
            OutputTarget::Stdout
        );

        assert_eq!(
            OutputTarget::from(OutputTarget::Path("hello/world".into()).to_string()),
            OutputTarget::Path("hello/world".into()),
        );
    }
}
