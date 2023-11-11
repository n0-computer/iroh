use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use console::{style, Emoji};
use futures::{Stream, StreamExt};
use indicatif::{
    HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressState,
    ProgressStyle,
};
use iroh::{
    client::quic::Iroh,
    rpc_protocol::{
        BlobDownloadRequest, DownloadLocation, NodeStatusResponse, ProviderService, SetTagOption,
        WrapOption,
    },
    ticket::blob::Ticket,
};
use iroh_bytes::{
    protocol::RequestToken,
    provider::{AddProgress, DownloadProgress},
    store::ValidateProgress,
    BlobFormat, Hash, HashAndFormat, Tag,
};
use iroh_net::{key::PublicKey, NodeAddr};
use quic_rpc::ServiceConnection;
use tokio::io::AsyncWriteExt;

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug, Clone)]
pub enum BlobCommands {
    /// Add data from PATH to the running node.
    Add(BlobAddOptions),
    /// Download data to the running node's database and provide it.
    ///
    /// In addition to downloading the data, you can also specify an optional output directory
    /// where the data will be exported to after it has been downloaded.
    Get {
        /// Ticket or Hash to use.
        #[clap(name = "TICKET OR HASH")]
        ticket: TicketOrHash,
        /// Additonal socket address to use to contact the node. Can be used multiple times.
        #[clap(long)]
        address: Vec<SocketAddr>,
        /// Override the Derp region to use to contact the node.
        #[clap(long)]
        derp_region: Option<u16>,
        /// Override to treat the blob as a raw blob or a hash sequence.
        #[clap(long)]
        recursive: Option<bool>,
        /// Override the ticket token.
        #[clap(long)]
        request_token: Option<RequestToken>,
        /// If set, the ticket's direct addresses will not be used.
        #[clap(long)]
        override_addresses: bool,
        /// NodeId of the provider.
        #[clap(long)]
        node: Option<PublicKey>,
        /// Directory or file in which to save the file(s).
        ///
        /// If set to `STDOUT` the output will be redirected to stdout.
        ///
        /// If not specified, the data will only be stored internally.
        #[clap(long, short)]
        out: Option<OutputTarget>,
        /// If set, the data will be moved to the output directory, and iroh will assume that it
        /// will not change.
        #[clap(long, default_value_t = false, global = true)]
        stable: bool,
        /// Tag to tag the data with.
        #[clap(long, global = true)]
        tag: Option<String>,
    },
    /// List availble content on the node.
    #[clap(subcommand)]
    List(ListCommands),
    /// Validate hashes on the running node.
    Validate {
        /// Repair the store by removing invalid data
        #[clap(long, default_value_t = false)]
        repair: bool,
    },
    /// Delete content on the node.
    #[clap(subcommand)]
    Delete(DeleteCommands),
    /// Get a ticket to share this blob.
    Share {
        /// Hash of the blob to share.
        hash: Hash,
        /// Include an optional authentication token in the ticket.
        #[clap(long)]
        token: Option<String>,
        /// Do not include DERP reion information in the ticket. (advanced)
        #[clap(long, conflicts_with = "derp_only", default_value_t = false)]
        no_derp: bool,
        /// Include only the DERP region information in the ticket. (advanced)
        #[clap(long, conflicts_with = "no_derp", default_value_t = false)]
        derp_only: bool,
        /// If the blob is a collection, the requester will also fetch the listed blobs.
        #[clap(long, default_value_t = false)]
        recursive: bool,
        /// Display the contents of this ticket too.
        #[clap(long, hide = true)]
        debug: bool,
    },
}

#[derive(Debug, Clone, derive_more::Display)]
pub enum TicketOrHash {
    Ticket(Ticket),
    Hash(Hash),
}

impl std::str::FromStr for TicketOrHash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(ticket) = Ticket::from_str(s) {
            return Ok(Self::Ticket(ticket));
        }
        if let Ok(hash) = Hash::from_str(s) {
            return Ok(Self::Hash(hash));
        }
        Err(anyhow!("neither a valid ticket or hash"))
    }
}

impl BlobCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Get {
                ticket,
                mut address,
                derp_region,
                recursive,
                request_token,
                override_addresses,
                node,
                out,
                stable,
                tag,
            } => {
                let (node_addr, hash, format, token) = match ticket {
                    TicketOrHash::Ticket(ticket) => {
                        let (node_addr, hash, blob_format, maybe_token) = ticket.into_parts();

                        // create the node address with the appropriate overrides
                        let node_addr = {
                            let NodeAddr { node_id, info } = node_addr;
                            let addresses = if override_addresses {
                                // use only the cli supplied ones
                                address
                            } else {
                                // use both the cli supploes ones and the ticket ones
                                address.extend(info.direct_addresses.into_iter());
                                address
                            };

                            NodeAddr::from_parts(node_id, derp_region, addresses)
                        };

                        // check if the blob format has an override
                        let blob_format = match recursive {
                            Some(true) => BlobFormat::HashSeq,
                            Some(false) => BlobFormat::Raw,
                            None => blob_format,
                        };

                        // check if the token has an override
                        let token = maybe_token.and(request_token);
                        (node_addr, hash, blob_format, token)
                    }
                    TicketOrHash::Hash(hash) => {
                        // check if the blob format has an override
                        let blob_format = match recursive {
                            Some(true) => BlobFormat::HashSeq,
                            Some(false) => BlobFormat::Raw,
                            None => BlobFormat::Raw,
                        };

                        let Some(node) = node else {
                            bail!("missing NodeId");
                        };

                        let node_addr = NodeAddr::from_parts(node, derp_region, address);
                        (node_addr, hash, blob_format, request_token)
                    }
                };

                if node_addr.info.is_empty() {
                    return Err(anyhow::anyhow!(
                        "no derp region provided and no direct addresses provided"
                    ));
                }
                let tag = match tag {
                    Some(tag) => SetTagOption::Named(Tag::from(tag)),
                    None => SetTagOption::Auto,
                };

                let (out_location, tmpfile) = match out {
                    None => (DownloadLocation::Internal, None),
                    Some(OutputTarget::Stdout) => {
                        let tmpfile = tempfile::NamedTempFile::new()?;
                        (
                            DownloadLocation::External {
                                path: tmpfile.path().into(),
                                in_place: false,
                            },
                            Some(tmpfile),
                        )
                    }
                    Some(OutputTarget::Path(path)) => {
                        let absolute = std::env::current_dir()?.join(&path);
                        tracing::info!(
                            "output path is {} -> {}",
                            path.display(),
                            absolute.display()
                        );
                        (
                            DownloadLocation::External {
                                path: absolute,
                                in_place: stable,
                            },
                            None,
                        )
                    }
                };

                let mut stream = iroh
                    .blobs
                    .download(BlobDownloadRequest {
                        hash,
                        format,
                        peer: node_addr,
                        token,
                        out: out_location,
                        tag,
                    })
                    .await?;

                if let Some(_tmpfile) = tmpfile {
                    // TODO

                    show_download_progress(hash, &mut stream).await?;
                    Ok(())
                } else {
                    show_download_progress(hash, &mut stream).await
                }
            }
            Self::List(cmd) => cmd.run(iroh).await,
            Self::Delete(cmd) => cmd.run(iroh).await,
            Self::Validate { repair } => validate(iroh, repair).await,
            Self::Add(opts) => {
                // TODO: This is where we are missing the request token from the running
                // node (last argument to run_with_opts).
                add_with_opts(iroh, opts, None).await
            }
            Self::Share {
                hash,
                token,
                no_derp,
                derp_only,
                recursive,
                debug,
            } => {
                let NodeStatusResponse { addr, .. } = iroh.node.status().await?;
                let node_addr = if no_derp {
                    NodeAddr::new(addr.node_id)
                        .with_direct_addresses(addr.direct_addresses().copied())
                } else if derp_only {
                    if let Some(region) = addr.derp_region() {
                        NodeAddr::new(addr.node_id).with_derp_region(region)
                    } else {
                        addr
                    }
                } else {
                    addr
                };

                let blob_reader = iroh
                    .blobs
                    .read(hash)
                    .await
                    .context("failed to retrieve blob info")?;
                let blob_status = if blob_reader.is_complete() {
                    "blob"
                } else {
                    "incomplete blob"
                };

                let format = if recursive {
                    BlobFormat::HashSeq
                } else {
                    BlobFormat::Raw
                };

                let request_token = token.map(RequestToken::new).transpose()?;

                let ticket =
                    Ticket::new(node_addr, hash, format, request_token).expect("correct ticket");
                println!(
                    "Ticket for {blob_status} {hash} ({})\n{ticket}",
                    HumanBytes(blob_reader.size())
                );
                if debug {
                    println!("{ticket:#?}")
                }
                Ok(())
            }
        }
    }
}

/// Options for the `blob add` command.
#[derive(clap::Args, Debug, Clone)]
pub struct BlobAddOptions {
    /// The source of the file or folder to add.
    ///
    /// If `STDIN` is specified, the data will be read from stdin.
    ///
    /// When left empty no content is added.
    #[clap(long)]
    pub source: Option<BlobSource>,

    /// Add in place
    ///
    /// Set this to true only if you are sure that the data in its current location
    /// will not change.
    #[clap(long, default_value_t = false)]
    pub in_place: bool,

    /// Tag to tag the data with.
    #[clap(long)]
    pub tag: Option<String>,

    /// Wrap the added file or directory in a collection.
    ///
    /// When adding a single file, without `wrap` the file is added as a single blob and no
    /// collection is created. When enabling `wrap` it also creates a collection with a
    /// single entry, where the entry's name is the filename and the entry's content is blob.
    ///
    /// When adding a directory, a collection is always created.
    /// Without `wrap`, the collection directly contains the entries from the added direcory.
    /// With `wrap`, the directory will be nested so that all names in the collection are
    /// prefixed with the directory name, thus preserving the name of the directory.
    ///
    /// When adding content from STDIN and setting `wrap` you also need to set `filename` to name
    /// the entry pointing to the content from STDIN.
    #[clap(long, default_value_t = false)]
    pub wrap: bool,

    /// Override the filename used for the entry in the created collection.
    ///
    /// Only supported `wrap` is set.
    /// Required when adding content from STDIN and setting `wrap`.
    #[clap(long, requires = "wrap")]
    pub filename: Option<String>,

    /// Do not print the all-in-one ticket to get the added data from this node.
    #[clap(long)]
    pub no_ticket: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ListCommands {
    /// List the available blobs on the running provider.
    Blobs,
    /// List the available blobs on the running provider.
    IncompleteBlobs,
    /// List the available collections on the running provider.
    Collections,
}

impl ListCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Blobs => {
                let mut response = iroh.blobs.list().await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {} ({})", item.path, item.hash, HumanBytes(item.size),);
                }
            }
            Self::IncompleteBlobs => {
                let mut response = iroh.blobs.list_incomplete().await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {}", item.hash, item.size);
                }
            }
            Self::Collections => {
                let mut response = iroh.blobs.list_collections().await?;
                while let Some(res) = response.next().await {
                    let res = res?;
                    let total_blobs_count = res.total_blobs_count.unwrap_or_default();
                    let total_blobs_size = res.total_blobs_size.unwrap_or_default();
                    println!(
                        "{}: {} {} {} ({})",
                        res.tag,
                        res.hash,
                        total_blobs_count,
                        if total_blobs_count > 1 {
                            "blobs"
                        } else {
                            "blob"
                        },
                        HumanBytes(total_blobs_size),
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum DeleteCommands {
    /// Delete the given blobs
    Blob {
        /// Blobs to delete
        #[arg(required = true)]
        hash: Hash,
    },
}

impl DeleteCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Blob { hash } => {
                let response = iroh.blobs.delete_blob(hash).await;
                if let Err(e) = response {
                    println!("Error: {}", e);
                }
            }
        }
        Ok(())
    }
}

pub async fn validate(iroh: &Iroh, repair: bool) -> Result<()> {
    let mut state = ValidateProgressState::new();
    let mut response = iroh.blobs.validate(repair).await?;

    while let Some(item) = response.next().await {
        match item? {
            ValidateProgress::Starting { total } => {
                state.starting(total);
            }
            ValidateProgress::Entry {
                id,
                hash,
                path,
                size,
            } => {
                state.add_entry(id, hash, path, size);
            }
            ValidateProgress::Progress { id, offset } => {
                state.progress(id, offset);
            }
            ValidateProgress::Done { id, error } => {
                state.done(id, error);
            }
            ValidateProgress::Abort(error) => {
                state.abort(error.to_string());
                break;
            }
            ValidateProgress::AllDone => {
                break;
            }
        }
    }
    Ok(())
}

struct ValidateProgressState {
    mp: MultiProgress,
    pbs: HashMap<u64, ProgressBar>,
    overall: ProgressBar,
    total: u64,
    errors: u64,
    successes: u64,
}

impl ValidateProgressState {
    fn new() -> Self {
        let mp = MultiProgress::new();
        let overall = mp.add(ProgressBar::new(0));
        overall.enable_steady_tick(Duration::from_millis(500));
        Self {
            mp,
            pbs: HashMap::new(),
            overall,
            total: 0,
            errors: 0,
            successes: 0,
        }
    }

    fn starting(&mut self, total: u64) {
        self.total = total;
        self.errors = 0;
        self.successes = 0;
        self.overall.set_position(0);
        self.overall.set_length(total);
        self.overall.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:60.cyan/blue}] {msg}")
                .unwrap()
                .progress_chars("=>-"),
        );
    }

    fn add_entry(&mut self, id: u64, hash: Hash, path: Option<String>, size: u64) {
        let pb = self.mp.insert_before(&self.overall, ProgressBar::new(size));
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {msg} {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})").unwrap()
            .progress_chars("=>-"));
        let msg = if let Some(path) = path {
            path
        } else {
            format!("outboard {}", hash)
        };
        pb.set_message(msg);
        pb.set_position(0);
        pb.set_length(size);
        pb.enable_steady_tick(Duration::from_millis(500));
        self.pbs.insert(id, pb);
    }

    fn progress(&mut self, id: u64, progress: u64) {
        if let Some(pb) = self.pbs.get_mut(&id) {
            pb.set_position(progress);
        }
    }

    fn abort(self, error: String) {
        let error_line = self.mp.add(ProgressBar::new(0));
        error_line.set_style(ProgressStyle::default_bar().template("{msg}").unwrap());
        error_line.set_message(error);
    }

    fn done(&mut self, id: u64, error: Option<String>) {
        if let Some(pb) = self.pbs.remove(&id) {
            let ok_char = style(Emoji("✔", "OK")).green();
            let fail_char = style(Emoji("✗", "Error")).red();
            let ok = error.is_none();
            let msg = match error {
                Some(error) => format!("{} {} {}", pb.message(), fail_char, error),
                None => format!("{} {}", pb.message(), ok_char),
            };
            if ok {
                self.successes += 1;
            } else {
                self.errors += 1;
            }
            self.overall.set_position(self.errors + self.successes);
            self.overall.set_message(format!(
                "Overall {} {}, {} {}",
                self.errors, fail_char, self.successes, ok_char
            ));
            if ok {
                pb.finish_and_clear();
            } else {
                pb.set_style(ProgressStyle::default_bar().template("{msg}").unwrap());
                pb.finish_with_message(msg);
            }
        }
    }
}

/// Where the data should be read from.
#[derive(Debug, Clone, derive_more::Display, PartialEq, Eq)]
pub enum BlobSource {
    /// Reads from stdin
    #[display("STDIN")]
    Stdin,
    /// Reads from the provided path
    #[display("{}", _0.display())]
    Path(PathBuf),
}

impl From<String> for BlobSource {
    fn from(s: String) -> Self {
        if s == "STDIN" {
            return BlobSource::Stdin;
        }

        BlobSource::Path(s.into())
    }
}

/// Data source for adding data to iroh.
#[derive(Debug, Clone)]
pub enum BlobSourceIroh {
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

pub async fn add_with_opts<C: ServiceConnection<ProviderService>>(
    client: &iroh::client::Iroh<C>,
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
        Some(BlobSource::Stdin) => BlobSourceIroh::Stdin,
        Some(BlobSource::Path(path)) => BlobSourceIroh::LocalFs {
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

    add(client, source, tag, ticket, wrap).await
}

/// Add data to iroh, either from a path or, if path is `None`, from STDIN.
pub async fn add<C: ServiceConnection<ProviderService>>(
    client: &iroh::client::Iroh<C>,
    source: BlobSourceIroh,
    tag: SetTagOption,
    ticket: TicketOption,
    wrap: WrapOption,
) -> Result<()> {
    let (hash, format, entries) = match source {
        BlobSourceIroh::LocalFs { path, in_place } => {
            let absolute = path.canonicalize()?;
            println!("Adding {} as {}...", path.display(), absolute.display());

            // tell the node to add the data
            let stream = client
                .blobs
                .add_from_path(absolute, in_place, tag, wrap)
                .await?;
            aggregate_add_response(stream).await?
        }
        BlobSourceIroh::Stdin => {
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

pub async fn show_download_progress(
    hash: Hash,
    mut stream: impl Stream<Item = Result<DownloadProgress>> + Unpin,
) -> Result<()> {
    eprintln!("Fetching: {}", hash);
    let mp = MultiProgress::new();
    mp.set_draw_target(ProgressDrawTarget::stderr());
    let op = mp.add(make_overall_progress());
    let ip = mp.add(make_individual_progress());
    op.set_message(format!("{} Connecting ...\n", style("[1/3]").bold().dim()));
    let mut seq = false;
    while let Some(x) = stream.next().await {
        match x? {
            DownloadProgress::Connected => {
                op.set_message(format!("{} Requesting ...\n", style("[2/3]").bold().dim()));
            }
            DownloadProgress::FoundHashSeq { children, .. } => {
                op.set_message(format!(
                    "{} Downloading {} blob(s)\n",
                    style("[3/3]").bold().dim(),
                    children + 1,
                ));
                op.set_length(children + 1);
                op.reset();
                seq = true;
            }
            DownloadProgress::Found { size, child, .. } => {
                if seq {
                    op.set_position(child);
                } else {
                    op.finish_and_clear();
                }
                ip.set_length(size);
                ip.reset();
            }
            DownloadProgress::Progress { offset, .. } => {
                ip.set_position(offset);
            }
            DownloadProgress::Done { .. } => {
                ip.finish_and_clear();
            }
            DownloadProgress::NetworkDone {
                bytes_read,
                elapsed,
                ..
            } => {
                op.finish_and_clear();
                eprintln!(
                    "Transferred {} in {}, {}/s",
                    HumanBytes(bytes_read),
                    HumanDuration(elapsed),
                    HumanBytes((bytes_read as f64 / elapsed.as_secs_f64()) as u64)
                );
            }
            DownloadProgress::AllDone => {
                break;
            }
            _ => {}
        }
    }
    Ok(())
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

fn make_overall_progress() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template(
            "{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );
    pb
}

fn make_individual_progress() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_source() {
        assert_eq!(
            BlobSource::from(BlobSource::Stdin.to_string()),
            BlobSource::Stdin
        );

        assert_eq!(
            BlobSource::from(BlobSource::Path("hello/world".into()).to_string()),
            BlobSource::Path("hello/world".into()),
        );
    }

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
