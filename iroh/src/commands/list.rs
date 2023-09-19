use anyhow::Result;
use clap::Subcommand;
use futures::StreamExt;
use indicatif::HumanBytes;
use iroh::{
    client::quic::RpcClient,
    rpc_protocol::{
        ListBlobsRequest, ListIncompleteBlobsRequest, ListRootsRequest, ListRootsResponse,
    },
};

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// List the available blobs on the running provider.
    Blobs,
    /// List the available blobs on the running provider.
    IncompleteBlobs,
    /// List the available roots on the running provider.
    Roots,
}

impl Commands {
    pub async fn run(self, client: RpcClient) -> Result<()> {
        match self {
            Commands::Blobs => {
                let mut response = client.server_streaming(ListBlobsRequest).await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {} ({})", item.path, item.hash, HumanBytes(item.size),);
                }
            }
            Commands::IncompleteBlobs => {
                let mut response = client.server_streaming(ListIncompleteBlobsRequest).await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {}", item.hash, item.size);
                }
            }
            Commands::Roots => {
                let mut response = client.server_streaming(ListRootsRequest).await?;
                while let Some(item) = response.next().await {
                    let ListRootsResponse { name, hash, format } = item?;
                    let name = if let Ok(text) = std::str::from_utf8(&name) {
                        format!("\"{}\"", text)
                    } else {
                        hex::encode(&name)
                    };
                    println!("{}: {} {:?}", name, hash, format,);
                }
            }
        }
        Ok(())
    }
}
