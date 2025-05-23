#![allow(warnings)]
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use iroh::{
    discovery::dns::DnsDiscovery,
    endpoint::{ConnectionError, Endpoint},
    NodeAddr, RelayMap, RelayMode, RelayUrl, SecretKey,
};
use tokio::sync::RwLock;
use tracing::{info, warn};
use walkdir::WalkDir;

// Protocol ALPN for file sharing
const FILE_SHARE_ALPN: &[u8] = b"n0/iroh/file-share/0";

#[derive(Parser, Debug)]
#[command(name = "file-share")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Share files or directories on the network
    Share {
        /// Path to the file or directory to share
        #[clap(long)]
        path: PathBuf,
        /// Optional relay URL to use
        #[clap(long)]
        relay_url: Option<String>,
        /// Use relay only mode
        #[clap(long, default_value = "false")]
        relay_only: bool,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
struct FileMetadata {
    path: String,
    size: u64,
    hash: String,
    is_dir: bool,
}

#[derive(Debug, Clone)]
struct FileShare {
    metadata: FileMetadata,
    data: Option<Bytes>,
}

#[derive(Debug, Clone)]
struct FileShareServer {
    files: Arc<RwLock<std::collections::HashMap<String, FileShare>>>,
}

impl FileShareServer {
    fn new() -> Self {
        Self {
            files: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    async fn add_path(&self, path: &Path) -> Result<Vec<FileMetadata>> {
        let mut metadata_list = Vec::new();
        
        if path.is_file() {
            println!("Adding file: {}", path.display());
            let metadata = self.add_file(path).await?;
            metadata_list.push(metadata);
        } else if path.is_dir() {
            println!("Adding directory: {}", path.display());
            // First add the directory itself
            let dir_metadata = FileMetadata {
                path: path.to_string_lossy().to_string(),
                size: 0,
                hash: String::new(),
                is_dir: true,
            };
            let dir_share = FileShare {
                metadata: dir_metadata.clone(),
                data: None,
            };
            self.files.write().await.insert(path.to_string_lossy().to_string(), dir_share);
            metadata_list.push(dir_metadata);

            // Then add all files and subdirectories
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                let entry_path = entry.path();
                if entry_path == path {
                    continue; // Skip the root directory as we already added it
                }
                
                if entry_path.is_file() {
                    println!("Adding file: {}", entry_path.display());
                    let metadata = self.add_file(entry_path).await?;
                    metadata_list.push(metadata);
                } else if entry_path.is_dir() {
                    println!("Adding subdirectory: {}", entry_path.display());
                    let metadata = FileMetadata {
                        path: entry_path.to_string_lossy().to_string(),
                        size: 0,
                        hash: String::new(),
                        is_dir: true,
                    };
                    let file_share = FileShare {
                        metadata: metadata.clone(),
                        data: None,
                    };
                    self.files.write().await.insert(entry_path.to_string_lossy().to_string(), file_share);
                    metadata_list.push(metadata);
                }
            }
        }
        
        println!("Total items added: {}", metadata_list.len());
        Ok(metadata_list)
    }

    async fn add_file(&self, path: &Path) -> Result<FileMetadata> {
        let path_str = path.to_string_lossy().to_string();
        println!("Reading file: {}", path_str);
        let data = tokio::fs::read(path).await?;
        let size = data.len() as u64;
        let hash = blake3::hash(&data).to_string();
        
        let metadata = FileMetadata {
            path: path_str.clone(),
            size,
            hash,
            is_dir: false,
        };

        let file_share = FileShare {
            metadata: metadata.clone(),
            data: Some(Bytes::from(data)),
        };

        self.files.write().await.insert(path_str, file_share);
        println!("Added file: {} ({} bytes)", path_str, size);
        Ok(metadata)
    }

    async fn get_file(&self, path: &str) -> Option<FileShare> {
        println!("Looking up file: {}", path);
        let file = self.files.read().await.get(path).cloned();
        if file.is_none() {
            println!("File not found: {}", path);
        }
        file
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli: Cli = Cli::parse();
    match cli.command {
        Commands::Share {
            path,
            relay_url,
            relay_only,
        } => {

            share_path(path, relay_url, relay_only).await?;
        }
    }

    Ok(())
}

async fn share_path(
    path: PathBuf,
    relay_url: Option<String>,
    relay_only: bool,
) -> Result<()> {
    // Initialize the file share server
    let server = FileShareServer::new();
    
    // Add the path to the server
    let metadata_list = server.add_path(&path).await?;
    
    // Print information about shared files
    println!("Sharing {} items:", metadata_list.len());
    for metadata in &metadata_list {
        if metadata.is_dir {
            println!("Directory: {}", metadata.path);
        } else {
            println!("File: {} ({} bytes)", metadata.path, metadata.size);
        }
    }

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

    // Get the node address
    let node_id = endpoint.node_id();
    println!("Node ID: {}", node_id);
    
    // Print connection information
    let node_addr = endpoint.node_addr().await?;
    println!("Direct addresses:");
    for addr in node_addr.direct_addresses {
        println!("  {}", addr);
    }
    if let Some(relay_url) = node_addr.relay_url {
        println!("Relay URL: {}", relay_url);
    }

    // Keep the server running and handle incoming connections
    while let Some(incoming) = endpoint.accept().await {
        let server = server.clone();
        tokio::spawn(async move {
            let connection = match incoming.accept() {
                Ok(conn) => {
                    let conn = conn.await?;
                    let node_id = conn.remote_node_id()?;
                    println!("New connection from node: {}", node_id);
                    conn
                }
                Err(e) => {
                    println!("Connection failed: {}", e);
                    return Ok::<_, anyhow::Error>(());
                }
            };

            let (mut send, mut recv) = connection.accept_bi().await?;
            
            // Read the request
            let request = recv.read_to_end(1024 * 1024).await?;
            if request.is_empty() {
                println!("Received empty request");
                return Ok::<_, anyhow::Error>(());
            }
            
            if request == b"LIST" {
                println!("Received LIST request");
                // Send the file list
                let files: Vec<FileMetadata> = server.files.read().await
                    .values()
                    .map(|f| f.metadata.clone())
                    .collect();
                let response = serde_json::to_vec(&files)?;
                send.write_all(&response).await?;
                send.finish()?;
                println!("Sent file list ({} files)", files.len());
            } else {
                // Request is a file path
                let path = String::from_utf8(request)?;
                println!("Received request for file: {}", path);
                if let Some(file) = server.get_file(&path).await {
                    if let Some(data) = file.data {
                        send.write_all(&data).await?;
                        send.finish()?;
                        println!("Sent file: {} ({} bytes)", path, data.len());
                    } else {
                        println!("File not found: {}", path);
                    }
                } else {
                    println!("File not found: {}", path);
                }
            }
            
            // Wait for the connection to close
            connection.closed().await;
            println!("Connection closed");
            Ok::<_, anyhow::Error>(())
        });
    }

    Ok(())
} 