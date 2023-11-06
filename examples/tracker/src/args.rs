//! Command line arguments.
use clap::{Parser, Subcommand};
use iroh::ticket::blob::Ticket;
use iroh_bytes::{Hash, HashAndFormat};
use std::{fmt::Display, str::FromStr};

use crate::NodeId;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Server(ServerArgs),
    Announce(AnnounceArgs),
    Query(QueryArgs),
}

#[derive(Parser, Debug)]
pub struct ServerArgs {
    /// The port to listen on.
    #[clap(long, default_value_t = 0xacacu16)]
    pub port: u16,

    #[clap(long)]
    pub quiet: bool,
}

/// Various ways to specify content.
#[derive(Debug, Clone, derive_more::From)]
pub enum ContentArg {
    Hash(Hash),
    HashAndFormat(HashAndFormat),
    Ticket(Ticket),
}

impl ContentArg {
    /// Get the hash and format of the content.
    pub fn hash_and_format(&self) -> HashAndFormat {
        match self {
            ContentArg::Hash(hash) => HashAndFormat::raw(*hash),
            ContentArg::HashAndFormat(haf) => *haf,
            ContentArg::Ticket(ticket) => HashAndFormat {
                hash: ticket.hash(),
                format: ticket.format(),
            },
        }
    }

    /// Get the host of the content. Only defined for tickets.
    pub fn host(&self) -> Option<NodeId> {
        match self {
            ContentArg::Hash(_) => None,
            ContentArg::HashAndFormat(_) => None,
            ContentArg::Ticket(ticket) => Some(ticket.node_addr().node_id),
        }
    }
}

impl Display for ContentArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentArg::Hash(hash) => Display::fmt(hash, f),
            ContentArg::HashAndFormat(haf) => Display::fmt(haf, f),
            ContentArg::Ticket(ticket) => Display::fmt(ticket, f),
        }
    }
}

impl FromStr for ContentArg {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(hash) = Hash::from_str(s) {
            Ok(hash.into())
        } else if let Ok(haf) = HashAndFormat::from_str(s) {
            Ok(haf.into())
        } else if let Ok(ticket) = Ticket::from_str(s) {
            Ok(ticket.into())
        } else {
            anyhow::bail!("invalid hash and format")
        }
    }
}

#[derive(Parser, Debug)]
pub struct AnnounceArgs {
    /// the tracker to announce to
    #[clap(long)]
    pub tracker: NodeId,

    /// the port to use for announcing
    #[clap(long)]
    pub port: Option<u16>,

    /// The host to announce. Not needed if content is a ticket.
    #[clap(long)]
    pub host: Option<NodeId>,

    /// The content to announce.
    ///
    /// Content can be specified as a hash, a hash and format, or a ticket.
    /// If a hash is specified, the format is assumed to be raw.
    /// Unless a ticket is specified, the host must be specified.
    pub content: Vec<ContentArg>,

    /// Announce that the peer has only partial data.
    #[clap(long)]
    pub partial: bool,
}

#[derive(Parser, Debug)]
pub struct QueryArgs {
    #[clap(long)]
    pub tracker: NodeId,

    /// the port to use for querying
    #[clap(long)]
    pub port: Option<u16>,

    /// The content to find hosts for.
    pub content: ContentArg,

    /// Ask for hosts that were announced as having just partial data
    #[clap(long)]
    pub partial: bool,

    /// Ask for hosts that were recently checked and found to have some data
    #[clap(long)]
    pub verified: bool,
}
