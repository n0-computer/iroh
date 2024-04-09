use anyhow::{bail, Result};
use clap::Parser;
use derive_more::FromStr;
use futures::TryStreamExt;
use iroh::base::base32::fmt_short;

use iroh::sync::{Author, AuthorId};
use iroh::{client::Iroh, rpc_protocol::ProviderService};
use quic_rpc::ServiceConnection;

use crate::config::ConsoleEnv;

#[derive(Debug, Clone, Parser)]
pub enum AuthorCommands {
    /// Set the active author (only works within the Iroh console).
    Switch { author: AuthorId },
    /// Create a new author.
    New {
        /// Switch to the created author (only in the Iroh console).
        #[clap(long)]
        switch: bool,
    },
    /// Delete an author.
    Delete { author: AuthorId },
    /// Export an author
    Export { author: AuthorId },
    /// Import an author
    Import { author: String },
    /// List authors.
    #[clap(alias = "ls")]
    List,
}

impl AuthorCommands {
    pub async fn run<C>(self, iroh: &Iroh<C>, env: &ConsoleEnv) -> Result<()>
    where
        C: ServiceConnection<ProviderService>,
    {
        match self {
            Self::Switch { author } => {
                env.set_author(author)?;
                println!("Active author is now {}", fmt_short(author.as_bytes()));
            }
            Self::List => {
                let mut stream = iroh.authors.list().await?;
                while let Some(author_id) = stream.try_next().await? {
                    println!("{}", author_id);
                }
            }
            Self::New { switch } => {
                if switch && !env.is_console() {
                    bail!("The --switch flag is only supported within the Iroh console.");
                }

                let author_id = iroh.authors.create().await?;
                println!("{}", author_id);

                if switch {
                    env.set_author(author_id)?;
                    println!("Active author is now {}", fmt_short(author_id.as_bytes()));
                }
            }
            Self::Delete { author } => {
                iroh.authors.delete(author).await?;
                println!("Deleted author {}", fmt_short(author.as_bytes()));
            }
            Self::Export { author } => match iroh.authors.export(author).await? {
                Some(author) => {
                    println!("{}", author);
                }
                None => {
                    println!("No author found {}", fmt_short(author));
                }
            },
            Self::Import { author } => match Author::from_str(&author) {
                Ok(author) => {
                    let id = author.id();
                    iroh.authors.import(author).await?;
                    println!("Imported {}", fmt_short(id));
                }
                Err(err) => {
                    eprintln!("Invalid author key: {}", err);
                }
            },
        }
        Ok(())
    }
}
