use chrono::Utc;
use std::{io::Write, path::PathBuf};
use anyhow::{Ok, Result};
use tabwriter::TabWriter;
use clap::Subcommand;

use crate::fake::{FakeDB, Space, SpaceRef, SpacePath};
use crate::config::Config;
use crate::net::tls::Keypair;

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// List known docs
    List {
        space_path: Option<SpacePath>
    },
    /// Create a new document
    New {
        /// Suggested Label for the document
        label: String,
        /// Network that will host the document, defaults to your home network
        #[clap(long, short, default_value = "default.iroh.network")]
        network: String
    },
    /// Join an existing document
    Join { token: String },
    /// Invite a new member to a document
    Invite { document: SpaceRef },
    /// Read a blob from a document
    Read {
        /// location or prefix to read
        document_path: String,
        /// agree to any large file warnings
        #[clap(short, long)]
        yes: bool
    },
    /// Add a blob to a document
    Write {
        document_path: SpacePath,
        value: PathBuf,
    },
    /// Delete a blob from a document, or delete a document entirely
    Delete {
        /// location or prefix to delete
        document_path: SpacePath,
        /// delete the entire document
        #[clap(long)]
        all: bool,
        /// pre-agree to any warnings
        #[clap(short, long)]
        yes: bool
    },
    /// Change a document label
    #[clap(alias = "rename")]
    Relabel { from: String, to: String },
    /// Update a document to the latest version
    Sync {},
    /// Link a Space to a filesystem directory
    LinkDir {
        /// The Space to link (label or id)
        document: SpaceRef,
        /// The directory to link
        dir: PathBuf,
    },
}

pub async fn run(command: Commands, config: &Config) -> anyhow::Result<()> {
    match command {
        Commands::List { space_path } => {
            match space_path {
                None => { list(config) }
                Some(path) => { list_path(config, path) }
            }
        },
        Commands::New { label, network } => new(config, network, label),
        Commands::Join { token } => join(config, token),
        Commands::Read { document_path, yes } => read(config, document_path, yes),
        Commands::Write { document_path, value } => write(config, document_path, value),
        Commands::Invite { document } => invite(config, document),
        Commands::Delete { document_path, all, yes } => {
            if all {
                delete_entire_document(config, document_path, yes)
            } else {
                delete(config, document_path, yes)
            }
        },
        Commands::Relabel { from, to } => relabel(config, from, to),
        Commands::Sync {} => sync(config),
        Commands::LinkDir { dir, document } => link_dir(config, document, dir),
    }
}

fn list(_config: &Config) -> Result<()> {
    let path = FakeDB::default_path()?;
    let db = FakeDB::load_or_create(&path)?;
    let mut tw = TabWriter::new(vec![]).padding(4);
    tw.write_all(b"Label\tID\tUpdated\n")?;
    for document in db.docs {
        let time: std::time::Duration = std::time::Duration::from_secs((Utc::now() - document.updated_at).num_seconds() as u64);
        let time = humantime::format_duration(time).to_string();
        tw.write_all(format!("{}\t{}\t{} ago\n", document.label, document.id, time).as_bytes())?;
    }
    tw.flush()?;
    let out = String::from_utf8(tw.into_inner()?)?;
    println!("{}", out);
    Ok(())
}

fn list_path(_config: &Config, path: SpacePath) -> Result<()> {
    println!("docs list command: {path}");
    Ok(())
}

fn new(_config: &Config, network: String, label: String) -> Result<()> {
    let path = FakeDB::default_path()?;
    let mut db = FakeDB::load_or_create(&path)?;

    let kp = Keypair::generate();
    let id = data_encoding::BASE32_NOPAD.encode(kp.public().as_bytes());
    let priv_key = data_encoding::BASE32_NOPAD.encode(&kp.secret().to_bytes());

    let document = Space {
        label: label.clone(),
        id: id.clone(),
        network,
        private_key: priv_key,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.docs.push(document);
    db.save(&path)?;
    println!("created document: {} with id: {}", label, id);
    Ok(())
}

fn invite(_config: &Config, document: SpaceRef) -> Result<()> {
    println!("here's your invite code for {document}. Send it to your friend
have your friend run `iroh docs join <TOKEN>` to join the document

    {}", document.clone().as_string().chars().rev().collect::<String>());
    Ok(())
}

fn join(_config: &Config, _token: String) -> Result<()> {
    println!("docs join command");
    Ok(())
}

fn read(_config: &Config, _document_path: String, _skip_warnings: bool) -> Result<()> {
    println!("docs read command");
    Ok(())
}

fn write(_config: &Config, document_path: SpacePath, _value: PathBuf) -> Result<()> {
    let path = FakeDB::default_path()?;
    let mut db = FakeDB::load_or_create(&path)?;
    let mut found = false;
    for mut document in db.docs.iter_mut() {
        if document_path.clone().as_string().starts_with(document.label.as_str()) {
            document.updated_at = Utc::now();
            found = true;
            break;
        }
    }

    if !found {
        anyhow::bail!("document not found: {document_path}");
    }

    db.save(&path)?;
    println!("wrote to {document_path}");
    Ok(())
}

fn delete_entire_document(_config: &Config, document_path: SpacePath, _skip_warnings: bool) -> Result<()> {
    println!("entire document {document_path} deleted");
    Ok(())
}

fn delete(_config: &Config, document_path: SpacePath, _skip_warnings: bool) -> Result<()> {
    println!("deleted {document_path}");
    Ok(())
}

fn relabel(_config: &Config, from: String, to: String) -> Result<()> {
    let path = FakeDB::default_path()?;
    let mut db = FakeDB::load_or_create(&path)?;
    let mut found = false;
    for mut document in db.docs.iter_mut() {
        if document.label == from {
            document.label = to.clone();
            found = true;
            break;
        }
    }

    if !found {
        anyhow::bail!("document not found: {}", from);
    }

    db.save(&path)?;
    println!("relabelled document: {} to {}", from, to);
    Ok(())
}

fn sync(_config: &Config) -> Result<()> {
    println!("docs sync command");
    Ok(())
}

fn link_dir(_config: &Config, document: SpaceRef, dir: PathBuf) -> Result<()> {
    println!("linking {} to {}", document, dir.display());
    Ok(())
}