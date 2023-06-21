use chrono::Utc;
use std::{io::Write, path::PathBuf};
use anyhow::{Ok, Result};
use tabwriter::TabWriter;
use clap::Subcommand;

use crate::fake::{FakeDB, Space, SpaceRef, SpacePath};
use crate::config::Config;
use iroh_bytes::Keypair;

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// List known spaces
    List {},
    /// Create a new space
    New {
        /// Suggested Label for the space
        label: String,
        /// Network that will host the space, defaults to your home network
        #[clap(long, short, default_value = "default.iroh.network")]
        network: String
    },
    /// Join an existing space
    Join { token: String },
    /// Invite a new member to a space
    Invite { space: SpaceRef },
    /// Read a blob from a space
    Read {
        /// location or prefix to read
        space_path: String,
        /// agree to any large file warnings
        #[clap(short, long)]
        yes: bool
    },
    /// Add a blob to a space
    Write {
        space_path: SpacePath,
        value: PathBuf,
    },
    /// Delete a blob from a space, or delete a space entirely
    Delete {
        /// location or prefix to delete
        space_path: SpacePath,
        /// delete the entire space
        #[clap(long)]
        all: bool,
        /// pre-agree to any warnings
        #[clap(short, long)]
        yes: bool
    },
    /// Change a space label
    #[clap(alias = "rename")]
    Relabel { from: String, to: String },
    /// Update a space to the latest version
    Sync {},
    /// Link a Space to a filesystem directory
    LinkDir {
        /// The Space to link (label or id)
        space: SpaceRef,
        /// The directory to link
        dir: PathBuf,
    },
}

pub async fn run(command: Commands, config: &Config) -> anyhow::Result<()> {
    match command {
        Commands::List {} => list(config),
        Commands::New { label, network } => new(config, network, label),
        Commands::Join { token } => join(config, token),
        Commands::Read { space_path, yes } => read(config, space_path, yes),
        Commands::Write { space_path, value } => write(config, space_path, value),
        Commands::Invite { space } => invite(config, space),
        Commands::Delete { space_path, all, yes } => {
            if all {
                delete_entire_space(config, space_path, yes)
            } else {
                delete(config, space_path, yes)
            }
        },
        Commands::Relabel { from, to } => relabel(config, from, to),
        Commands::Sync {} => sync(config),
        Commands::LinkDir { dir, space } => link_dir(config, space, dir),
    }
}

fn list(_config: &Config) -> Result<()> {
    let path = FakeDB::default_path()?;
    let db = FakeDB::load_or_create(&path)?;
    let mut tw = TabWriter::new(vec![]).padding(4);
    tw.write_all(b"Label\tID\tUpdated\n")?;
    for space in db.spaces {
        let time: std::time::Duration = std::time::Duration::from_secs((Utc::now() - space.updated_at).num_seconds() as u64);
        let time = humantime::format_duration(time).to_string();
        tw.write_all(format!("{}\t{}\t{} ago\n", space.label, space.id, time).as_bytes())?;
    }
    tw.flush()?;
    let out = String::from_utf8(tw.into_inner()?)?;
    println!("{}", out);
    Ok(())
}

fn new(_config: &Config, network: String, label: String) -> Result<()> {
    let path = FakeDB::default_path()?;
    let mut db = FakeDB::load_or_create(&path)?;

    let kp = Keypair::generate();
    let id = data_encoding::BASE32_NOPAD.encode(kp.public().as_bytes());
    let priv_key = data_encoding::BASE32_NOPAD.encode(&kp.secret().to_bytes());

    let space = Space {
        label: label.clone(),
        id: id.clone(),
        network,
        private_key: priv_key,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    db.spaces.push(space);
    db.save(&path)?;
    println!("created space: {} with id: {}", label, id);
    Ok(())
}

fn invite(_config: &Config, space: SpaceRef) -> Result<()> {
    println!("here's your invite code for {space}. Send it to your friend
have your friend run `iroh spaces join <TOKEN>` to join the space

    {}", space.clone().as_string().chars().rev().collect::<String>());
    Ok(())
}

fn join(_config: &Config, _token: String) -> Result<()> {
    println!("spaces join command");
    Ok(())
}

fn read(_config: &Config, _space_path: String, _skip_warnings: bool) -> Result<()> {
    println!("spaces read command");
    Ok(())
}

fn write(_config: &Config, space_path: SpacePath, _value: PathBuf) -> Result<()> {
    let path = FakeDB::default_path()?;
    let mut db = FakeDB::load_or_create(&path)?;
    let mut found = false;
    for mut space in db.spaces.iter_mut() {
        if space_path.clone().as_string().starts_with(space.label.as_str()) {
            space.updated_at = Utc::now();
            found = true;
            break;
        }
    }

    if !found {
        anyhow::bail!("space not found: {space_path}");
    }

    db.save(&path)?;
    println!("wrote to {space_path}");
    Ok(())
}

fn delete_entire_space(_config: &Config, space_path: SpacePath, _skip_warnings: bool) -> Result<()> {
    println!("entire space {space_path} deleted");
    Ok(())
}

fn delete(_config: &Config, space_path: SpacePath, _skip_warnings: bool) -> Result<()> {
    println!("deleted {space_path}");
    Ok(())
}

fn relabel(_config: &Config, from: String, to: String) -> Result<()> {
    let path = FakeDB::default_path()?;
    let mut db = FakeDB::load_or_create(&path)?;
    let mut found = false;
    for mut space in db.spaces.iter_mut() {
        if space.label == from {
            space.label = to.clone();
            found = true;
            break;
        }
    }

    if !found {
        anyhow::bail!("space not found: {}", from);
    }

    db.save(&path)?;
    println!("relabelled space: {} to {}", from, to);
    Ok(())
}

fn sync(_config: &Config) -> Result<()> {
    println!("spaces sync command");
    Ok(())
}

fn link_dir(_config: &Config, space: SpaceRef, dir: PathBuf) -> Result<()> {
    println!("linking {} to {}", space, dir.display());
    Ok(())
}