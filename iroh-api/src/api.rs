use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::{Config, CONFIG_FILE_NAME, ENV_PREFIX};
#[cfg(feature = "testing")]
use crate::p2p::MockP2p;
use crate::p2p::{ClientP2p, P2p};
use anyhow::Result;
use cid::Cid;
use futures::future::{BoxFuture, LocalBoxFuture};
use futures::stream::LocalBoxStream;
use futures::FutureExt;
use futures::Stream;
use futures::StreamExt;
use iroh_resolver::resolver::{OutPrettyReader, Path as IpfsPath};
use iroh_resolver::{resolver, unixfs_builder};
use iroh_rpc_client::Client;
use iroh_rpc_client::StatusTable;
use iroh_util::{iroh_config_path, make_config};
#[cfg(feature = "testing")]
use mockall::automock;
use relative_path::RelativePathBuf;
use tokio::io::AsyncRead;

pub struct Iroh {
    client: Client,
}

pub enum OutType<R>
where
    R: AsyncRead + Unpin + ?Sized,
{
    Dir,
    Reader(Box<R>),
}

// Note: `#[async_trait]` is deliberately not in use for this trait, because it
// became very hard to express what we wanted once streams were involved.
// Instead we spell things out explicitly without magic.

#[cfg_attr(feature= "testing", automock(type P = MockP2p;))]
pub trait Api {
    type P: P2p;

    fn p2p(&self) -> Result<Self::P>;

    fn get<'a>(
        &'a self,
        ipfs_path: &'a IpfsPath,
        output_path: Option<&'a Path>,
    ) -> LocalBoxFuture<'_, Result<()>>;
    fn get_stream<'a>(
        &'a self,
        ipfs_path: &'a IpfsPath,
    ) -> LocalBoxStream<'_, Result<(RelativePathBuf, OutType<OutPrettyReader<Client>>)>>;
    fn add<'a>(
        &'a self,
        path: &'a Path,
        recursive: bool,
        no_wrap: bool,
    ) -> LocalBoxFuture<'_, Result<Cid>>;
    fn check(&self) -> BoxFuture<'_, StatusTable>;
    fn watch(&self) -> LocalBoxFuture<'static, LocalBoxStream<'static, StatusTable>>;
}

impl Iroh {
    pub async fn new(
        config_path: Option<&Path>,
        overrides_map: HashMap<String, String>,
    ) -> Result<Self> {
        let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
        let sources = vec![Some(cfg_path), config_path.map(PathBuf::from)];
        let config = make_config(
            // default
            Config::default(),
            // potential config files
            sources,
            // env var prefix for this config
            ENV_PREFIX,
            // map of present command line arguments
            overrides_map,
        )
        .unwrap();

        let client = Client::new(config.rpc_client).await?;

        Ok(Iroh::from_client(client))
    }

    fn from_client(client: Client) -> Self {
        Self { client }
    }

    /// take a stream of blocks as from `get_stream` and write them to the filesystem
    pub async fn save_get_stream<R>(
        root_path: &Path,
        blocks: impl Stream<Item = Result<(RelativePathBuf, OutType<R>)>>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        tokio::pin!(blocks);
        while let Some(block) = blocks.next().await {
            let (path, out) = block?;
            let full_path = path.to_path(root_path);
            match out {
                OutType::Dir => {
                    tokio::fs::create_dir_all(full_path).await?;
                }
                OutType::Reader(mut reader) => {
                    if let Some(parent) = path.parent() {
                        tokio::fs::create_dir_all(parent.to_path(root_path)).await?;
                    }
                    let mut f = tokio::fs::File::create(full_path).await?;
                    tokio::io::copy(&mut reader, &mut f).await?;
                }
            }
        }
        Ok(())
    }
}

impl Api for Iroh {
    type P = ClientP2p;

    fn p2p(&self) -> Result<ClientP2p> {
        let p2p_client = self.client.try_p2p()?;
        Ok(ClientP2p::new(p2p_client.clone()))
    }

    fn get<'a>(
        &'a self,
        ipfs_path: &'a IpfsPath,
        output_path: Option<&'a Path>,
    ) -> LocalBoxFuture<'_, Result<()>> {
        // TODO(faassen) this should be testable but right now can't be
        let root_path = if let Some(output_path) = output_path {
            output_path
        } else {
            // TODO(faassen) needs to fall back to CID
            Path::new(".")
        };
        // let root_path = output_path.unwrap_or_else(|| Path::new("."));
        Iroh::save_get_stream(root_path, self.get_stream(ipfs_path)).boxed_local()
    }

    fn get_stream<'a>(
        &'a self,
        ipfs_path: &'a IpfsPath,
    ) -> LocalBoxStream<'_, Result<(RelativePathBuf, OutType<OutPrettyReader<Client>>)>> {
        tracing::debug!("get {:?}", ipfs_path);
        let resolver = iroh_resolver::resolver::Resolver::new(self.client.clone());
        let results = resolver.resolve_recursive_with_paths(ipfs_path.clone());
        async_stream::try_stream! {
            tokio::pin!(results);
            while let Some(res) = results.next().await {
                let (relative_ipfs_path, out) = res?;
                let relative_path = RelativePathBuf::from_path(&relative_ipfs_path.to_string_without_type())?;
                if out.is_dir() {
                    yield (relative_path, OutType::Dir);
                } else {
                    let reader = out.pretty(resolver.clone(), Default::default())?;
                    yield (relative_path, OutType::Reader(Box::new(reader)));
                }
            }
        }
        .boxed_local()
    }

    fn add<'a>(
        &'a self,
        path: &'a Path,
        recursive: bool,
        no_wrap: bool,
    ) -> LocalBoxFuture<'_, Result<Cid>> {
        async move {
            let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
                client: Box::new(&self.client),
            };
            if path.is_dir() {
                unixfs_builder::add_dir(Some(&providing_client), path, !no_wrap, recursive).await
            } else if path.is_file() {
                unixfs_builder::add_file(Some(&providing_client), path, !no_wrap).await
            } else {
                anyhow::bail!("can only add files or directories");
            }
        }
        .boxed_local()
    }

    fn check(&self) -> BoxFuture<'_, StatusTable> {
        async { self.client.check().await }.boxed()
    }

    fn watch(
        &self,
    ) -> LocalBoxFuture<'static, LocalBoxStream<'static, iroh_rpc_client::StatusTable>> {
        let client = self.client.clone();
        async { client.watch().await.boxed_local() }.boxed_local()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;

    #[tokio::test]
    async fn test_save_get_stream() {
        let stream = Box::pin(futures::stream::iter(vec![
            Ok((RelativePathBuf::from_path("a").unwrap(), OutType::Dir)),
            Ok((
                RelativePathBuf::from_path("b").unwrap(),
                OutType::Reader(Box::new(std::io::Cursor::new("hello"))),
            )),
        ]));
        // TODO(faassen) use tempfile crate so things get cleaned up
        Iroh::save_get_stream(Path::new("/tmp"), stream)
            .await
            .unwrap();
    }
}
