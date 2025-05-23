#![allow(warnings)]
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use iroh::{
    endpoint::Endpoint,
    NodeId, RelayMap, RelayMode, RelayUrl, SecretKey,
};

// Protocol ALPN for file sharing
const FILE_SHARE_ALPN: &[u8] = b"n0/iroh/file-share/0";

#[derive(Parser, Debug)]
#[command(name = "file-download")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Download files from a peer
    Download {
        /// Node ID of the peer to connect to
        #[clap(long)]
        node_id: String,
        /// Path to save downloaded files
        #[clap(long)]
        output_path: PathBuf,
        /// Optional relay URL to use
        #[clap(long)]
        relay_url: Option<String>,
        /// Use relay only mode
        #[clap(long, default_value = "false")]
        relay_only: bool,
    },
}

#[derive(serde::Deserialize)]
struct FileMetadata {
    path: String,
    size: u64,
    hash: String,
    is_dir: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli: Cli = Cli::parse();

    match cli.command {
        Commands::Download {
            node_id,
            output_path,
            relay_url,
            relay_only,
        } => {
            download_files(node_id, output_path, relay_url, relay_only).await?;
        }
    }

    Ok(())
}

async fn download_files(
    node_id: String,
    output_path: PathBuf,
    relay_url: Option<String>,
    relay_only: bool,
) -> Result<()> {
    println!("Connecting to peer: {}", node_id);
    
    // Set up the endpoint
    let secret_key = SecretKey::generate(rand::rngs::OsRng);
    let relay_mode = match relay_url {
        Some(relay_url) => {
            println!("Using relay URL: {}", relay_url);
            let relay_url = RelayUrl::from_str(&relay_url)?;
            let relay_map = RelayMap::from_url(relay_url);
            RelayMode::Custom(relay_map)
        }
        None => {
            println!("Using default relay mode");
            RelayMode::Default
        }
    };

    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![FILE_SHARE_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .discovery_n0()
        .bind()
        .await?;

    // Parse the node ID
    let node_id = NodeId::from_str(&node_id)?;
    
    println!("Connecting to peer...");
    let connection = match endpoint.connect(node_id, FILE_SHARE_ALPN).await {
        Ok(conn) => {
            println!("Connected to peer!");
            conn
        }
        Err(e) => {
            anyhow::bail!("Failed to connect to peer: {}. Make sure the peer is online and you have the correct relay URL if needed.", e)
        }
    };

    // Create output directory if it doesn't exist
    if !output_path.exists() {
        std::fs::create_dir_all(&output_path)?;
    }

    // Request file list
    println!("Requesting file list...");
    let (mut send, mut recv) = connection.open_bi().await?;
    let list_request = b"LIST";
    send.write_all(list_request).await?;
    send.finish()?;
    println!("Sent LIST request");

    // Read the response
    let response = recv.read_to_end(1024 * 1024).await?;
    if response.is_empty() {
        anyhow::bail!("Received empty response from server");
    }
    
    println!("Received response of {} bytes", response.len());
    
    // Parse the file list
    let files: Vec<FileMetadata> = match serde_json::from_slice(&response) {
        Ok(files) => {
            println!("Successfully parsed file list");
            files
        }
        Err(e) => {
            println!("Failed to parse response: {}", e);
            println!("Raw response: {}", String::from_utf8_lossy(&response));
            anyhow::bail!("Failed to parse file list response: {}. Response was: {:?}", e, String::from_utf8_lossy(&response))
        }
    };
    println!("Found {} files to download", files.len());
    for file in &files {
        if file.is_dir {
            println!("Directory: {}", file.path);
        } else {
            println!("File: {} ({} bytes)", file.path, file.size);
        }
    }

    // Download each file
    for file in files {
        if file.is_dir {
            let dir_path = output_path.join(&file.path);
            std::fs::create_dir_all(dir_path)?;
            println!("Created directory: {}", file.path);
        } else {
            println!("Downloading: {} ({} bytes)", file.path, file.size);
            
            // Request the file
            let (mut send, mut recv) = connection.open_bi().await?;
            let path_bytes = file.path.as_bytes();
            send.write_all(path_bytes).await?;
            send.finish()?;
            println!("Sent request for file: {}", file.path);

            // Read the file data
            let file_data = recv.read_to_end(1024 * 1024).await?;
            if file_data.is_empty() {
                println!("Warning: Received empty file for {}", file.path);
                continue;
            }
            println!("Received {} bytes for file {}", file_data.len(), file.path);

            // Save the file
            let file_path = output_path.join(&file.path);
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&file_path, &file_data)?;
            println!("Saved: {} ({} bytes)", file.path, file_data.len());

            // Verify file size
            if file_data.len() as u64 != file.size {
                println!("Warning: File size mismatch for {}. Expected {} bytes, got {} bytes", 
                    file.path, file.size, file_data.len());
            }
        }
    }

    println!("Download complete!");
    Ok(())
} 