use anyhow::anyhow;
use clap::Parser;
use futures::StreamExt;
use iroh::{
    rpc_protocol::{
        AuthorCreateRequest, AuthorListRequest, DocGetRequest, DocJoinRequest, DocSetRequest,
        DocShareRequest, DocsImportRequest, ShareMode,
    },
    sync::PeerSource,
};
use iroh_sync::sync::{NamespaceId, AuthorId};

use super::RpcClient;

#[derive(Debug, Clone, Parser)]
pub enum Commands {
    Author {
        #[clap(subcommand)]
        command: Author,
    },
    Doc {
        id: NamespaceId,
        #[clap(subcommand)]
        command: Doc,
    },
}

impl Commands {
    pub async fn run(self, client: RpcClient) -> anyhow::Result<()> {
        match self {
            Commands::Author { command } => command.run(client).await,
            Commands::Doc { command, id } => command.run(client, id).await,
        }
    }
}

#[derive(Debug, Clone, Parser)]
pub enum Author {
    List,
    Create,
}

impl Author {
    pub async fn run(self, client: RpcClient) -> anyhow::Result<()> {
        match self {
            Author::List => {
                let mut stream = client.server_streaming(AuthorListRequest {}).await?;
                while let Some(author) = stream.next().await {
                    println!("{}", author??.author_id);
                }
            }
            Author::Create => {
                let author = client.rpc(AuthorCreateRequest).await??;
                println!("{}", author.author_id);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Parser)]
pub enum Doc {
    Join {
        peers: Vec<PeerSource>,
    },
    Import {
        key: String,
        peers: Vec<PeerSource>,
    },
    Share {
        mode: ShareMode,
    },
    Set {
        author: AuthorId,
        key: String,
        value: String,
    },
    Get {
        key: String,

        #[clap(short, long)]
        prefix: bool,
    },
}

impl Doc {
    pub async fn run(self, client: RpcClient, doc_id: NamespaceId) -> anyhow::Result<()> {
        match self {
            Doc::Join { peers } => {
                // let peers = peers.map(|peer| PeerSource::try_from)?;
                let res = client.rpc(DocJoinRequest { doc_id, peers }).await??;
                println!("{:?}", res);
            }
            Doc::Import { key, peers } => {
                let key = hex::decode(key)?
                    .try_into()
                    .map_err(|_| anyhow!("invalid length"))?;
                let res = client.rpc(DocsImportRequest { key, peers }).await??;
                println!("{:?}", res);
            }
            Doc::Share { mode } => {
                let res = client.rpc(DocShareRequest { doc_id, mode }).await??;
                println!("{:?}", res);
            }
            Doc::Set { author, key, value } => {
                let res = client
                    .rpc(DocSetRequest {
                        author,
                        key: key.as_bytes().to_vec(),
                        value: value.as_bytes().to_vec(),
                        doc_id,
                    })
                    .await??;
                println!("{:?}", res);
            }
            Doc::Get { key, prefix } => {
                let res = client
                    .rpc(DocGetRequest {
                        key: key.as_bytes().to_vec(),
                        doc_id,
                        author: None,
                        prefix,
                    })
                    .await??;
                println!("{:?}", res);
            }
        }
        Ok(())
    }
}
