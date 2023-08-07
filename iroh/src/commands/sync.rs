use anyhow::anyhow;
use clap::Parser;
use futures::StreamExt;
use indicatif::HumanBytes;
use iroh::{
    rpc_protocol::{
        AuthorCreateRequest, AuthorListRequest, DocGetRequest, DocGetResponse, DocJoinRequest,
        DocListRequest, DocListResponse, DocSetRequest, DocShareRequest, DocShareResponse,
        DocsCreateRequest, DocsImportRequest, DocsListRequest, ShareMode,
    },
    sync::PeerSource,
};
use iroh_sync::sync::{AuthorId, NamespaceId, SignedEntry};

use super::RpcClient;

#[derive(Debug, Clone, Parser)]
pub enum Commands {
    Author {
        #[clap(subcommand)]
        command: Author,
    },
    Docs {
        #[clap(subcommand)]
        command: Docs,
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
            Commands::Docs { command } => command.run(client).await,
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
pub enum Docs {
    List,
    Create,
    Import {
        key: String,
        #[clap(short, long)]
        peers: Vec<PeerSource>,
    },
}

impl Docs {
    pub async fn run(self, client: RpcClient) -> anyhow::Result<()> {
        match self {
            Docs::Create => {
                let res = client.rpc(DocsCreateRequest {}).await??;
                println!("{}", res.id);
            }
            Docs::Import { key, peers } => {
                let key = hex::decode(key)?
                    .try_into()
                    .map_err(|_| anyhow!("invalid length"))?;
                let res = client.rpc(DocsImportRequest { key, peers }).await??;
                println!("{:?}", res);
            }
            Docs::List => {
                let mut iter = client.server_streaming(DocsListRequest {}).await?;
                while let Some(doc) = iter.next().await {
                    println!("{}", doc??.id)
                }
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
        #[clap(short, long)]
        author: Option<AuthorId>,
        /// Include old entries for keys.
        #[clap(short, long)]
        old: bool,
    },
    List {
        /// Include old entries for keys.
        #[clap(short, long)]
        old: bool,
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
            Doc::Share { mode } => {
                let DocShareResponse { key, me } =
                    client.rpc(DocShareRequest { doc_id, mode }).await??;
                println!("key: {}", hex::encode(key));
                println!("me:  {}", me);
            }
            Doc::Set { author, key, value } => {
                let res = client
                    .rpc(DocSetRequest {
                        author_id: author,
                        key: key.as_bytes().to_vec(),
                        value: value.as_bytes().to_vec(),
                        doc_id,
                    })
                    .await??;
                println!("{}", fmt_entry(&res.entry));
            }
            Doc::Get {
                key,
                prefix,
                author,
                old: all,
            } => {
                let mut stream = client
                    .server_streaming(DocGetRequest {
                        key: key.as_bytes().to_vec(),
                        doc_id,
                        author_id: author,
                        prefix,
                        // todo: support option
                        latest: !all,
                    })
                    .await?;
                while let Some(res) = stream.next().await {
                    let DocGetResponse { entry } = res??;
                    println!("{}", fmt_entry(&entry));
                }
            }
            Doc::List { old: all } => {
                let mut stream = client
                    // TODO: fields
                    .server_streaming(DocListRequest {
                        doc_id,
                        latest: !all, // author: None,
                                      // prefix: None,
                    })
                    .await?;
                while let Some(res) = stream.next().await {
                    let DocListResponse { entry } = res??;
                    println!("{}", fmt_entry(&entry));
                }
            }
        }
        Ok(())
    }
}

fn fmt_entry(entry: &SignedEntry) -> String {
    let id = entry.entry().id();
    let key = std::str::from_utf8(id.key()).unwrap_or("<bad key>");
    let author = fmt_hash(id.author().as_bytes());
    let hash = entry.entry().record().content_hash();
    let hash = fmt_hash(hash.as_bytes());
    let len = HumanBytes(entry.entry().record().content_len());
    format!("@{author}: {key} = {hash} ({len})",)
}

fn fmt_hash(hash: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&hash.as_ref()[..5]);
    text.make_ascii_lowercase();
    format!("{}…", &text)
}
