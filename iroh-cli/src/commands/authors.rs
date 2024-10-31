//! Define the commands to manage authors.

use anyhow::{bail, Result};
use clap::Parser;
use derive_more::FromStr;
use futures_lite::StreamExt;
use iroh::{
    base::base32::fmt_short,
    client::Iroh,
    docs::{Author, AuthorId},
};

use crate::config::ConsoleEnv;

/// Commands to manage authors.
#[derive(Debug, Clone, Parser)]
pub enum AuthorCommands {
    /// Set the active author (Note: only works within the Iroh console).
    Switch { author: AuthorId },
    /// Create a new author.
    Create {
        /// Switch to the created author (Note: only works in the Iroh console).
        #[clap(long)]
        switch: bool,
    },
    /// Delete an author.
    Delete { author: AuthorId },
    /// Export an author.
    Export { author: AuthorId },
    /// Import an author.
    Import { author: String },
    /// Print the default author for this node.
    Default {
        /// Switch to the default author (Note: only works in the Iroh console).
        #[clap(long)]
        switch: bool,
    },
    /// List authors.
    #[clap(alias = "ls")]
    List,
}

impl AuthorCommands {
    /// Runs the author command given an iroh client and console environment.
    pub async fn run(self, iroh: &Iroh, env: &ConsoleEnv) -> Result<()> {
        match self {
            Self::Switch { author } => {
                env.set_author(author)?;
                println!("Active author is now {}", fmt_short(author.as_bytes()));
            }
            Self::List => {
                let mut stream = iroh.docs().author_list().await?;
                while let Some(author_id) = stream.try_next().await? {
                    println!("{}", author_id);
                }
            }
            Self::Default { switch } => {
                if switch && !env.is_console() {
                    bail!("The --switch flag is only supported within the Iroh console.");
                }
                let author_id = iroh.docs().author_default().await?;
                println!("{}", author_id);
                if switch {
                    env.set_author(author_id)?;
                    println!("Active author is now {}", fmt_short(author_id.as_bytes()));
                }
            }
            Self::Create { switch } => {
                if switch && !env.is_console() {
                    bail!("The --switch flag is only supported within the Iroh console.");
                }

                let author_id = iroh.docs().author_create().await?;
                println!("{}", author_id);

                if switch {
                    env.set_author(author_id)?;
                    println!("Active author is now {}", fmt_short(author_id.as_bytes()));
                }
            }
            Self::Delete { author } => {
                iroh.docs().author_delete(author).await?;
                println!("Deleted author {}", fmt_short(author.as_bytes()));
            }
            Self::Export { author } => match iroh.docs().author_export(author).await? {
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
                    iroh.docs().author_import(author).await?;
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
