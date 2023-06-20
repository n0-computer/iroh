use anyhow::Result;

use crate::config::Config;
use clap::Subcommand;

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// List known spaces
    List {},
    /// Create a new space
    New {},
    /// Join an existing space
    Join {},
    /// Add a blob to a space
    Insert {},
    /// Delete a blob from a space, or delete a space entirely
    Delete {},
    /// Change a space label
    Relabel {},
    /// Update a space to the latest version
    Sync {},
}

pub async fn run(command: Commands, config: &Config) -> anyhow::Result<()> {
    match command {
        Commands::List {} => list(config),
        Commands::New {} => new(config),
        Commands::Join {} => join(config),
        Commands::Insert {} => insert(config),
        Commands::Delete {} => delete(config),
        Commands::Relabel {} => relabel(config),
        Commands::Sync {} => sync(config),
    }
}

pub fn list(_config: &Config) -> Result<()> {
    println!("spaces list command");
    Ok(())
}
pub fn new(_config: &Config) -> Result<()> {
    println!("spaces create command");
    Ok(())
}
pub fn join(_config: &Config) -> Result<()> {
    println!("spaces join command");
    Ok(())
}
pub fn insert(_config: &Config) -> Result<()> {
    println!("spaces insert command");
    Ok(())
}
pub fn delete(_config: &Config) -> Result<()> {
    println!("spaces delete command");
    Ok(())
}
pub fn relabel(_config: &Config) -> Result<()> {
    println!("spaces relabel command");
    Ok(())
}
pub fn sync(_config: &Config) -> Result<()> {
    println!("spaces sync command");
    Ok(())
}
