#[derive(Subcommand, Debug, Clone)]
pub enum BlobsCommands {
    /// List local blobs
    List {},
    /// Fetch the data identified by HASH from a provider.
    Get {
        /// The hash to retrieve, as a Blake3 CID
        hash: Blake3Cid,
        /// PeerId of the provider
        #[clap(long, short)]
        peer: PeerId,
        /// Addresses of the provider.
        #[clap(long, short)]
        addrs: Vec<SocketAddr>,
        /// Directory in which to save the file(s), defaults to writing to STDOUT
        #[clap(long, short)]
        out: Option<PathBuf>,
        /// True to download a single blob, false (default) to download a collection and its children.
        #[clap(long, default_value_t = false)]
        single: bool,
    },
    /// Send blobs to a remote peer
    Push {},
    /// Validate hashes on the running provider.
    Validate {
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },

    /// Add data from PATH to the running provider's database.
    Create {
        /// The path to the file or folder to add
        path: PathBuf,
        /// RPC port
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// Fetch data from a provider using a ticket.
    ///
    /// The ticket contains all hash, authentication and connection information to connect
    /// to the provider.  It is a simpler, but slightly less flexible alternative to the
    /// `get` subcommand.
    GetTicket {
        /// Directory in which to save the file(s), defaults to writing to STDOUT
        #[clap(long, short)]
        out: Option<PathBuf>,
        /// Ticket containing everything to retrieve the data from a provider.
        ticket: Ticket,
    },
}
