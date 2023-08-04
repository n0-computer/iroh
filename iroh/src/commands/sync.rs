use clap::Parser;
use futures::StreamExt;
use iroh::rpc_protocol::{AuthorCreateRequest, AuthorListRequest};

use super::RpcClient;

#[derive(Debug, Clone, Parser)]
pub enum Commands {
    Author {
        #[clap(subcommand)]
        command: Author,
    },
}

impl Commands {
    pub async fn run(self, client: RpcClient) -> anyhow::Result<()> {
        match self {
            Commands::Author { command } => command.run(client).await,
        }
    }
}

#[derive(Debug, Clone, Parser)]
pub enum Author {
    List,
    Create,
    // Import {
    //     key: String,
    // },
    // Share {
    //     mode: ShareMode,
    //     author_id: AuthorId,
    // },
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
            // Commands::AuthorImport { key } => todo!(),
            // Commands::AuthorShare { mode, author_id } => todo!(),
        }
        Ok(())
    }
}
