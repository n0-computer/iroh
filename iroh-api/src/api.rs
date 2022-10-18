use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::{Config, CONFIG_FILE_NAME, ENV_PREFIX};
#[cfg(feature = "testing")]
use crate::p2p::MockP2p;
use crate::p2p::{ClientP2p, P2p};
use crate::{AddEvent, Cid, IpfsPath};
use anyhow::Result;
use futures::future::{BoxFuture, LocalBoxFuture};
use futures::stream::LocalBoxStream;
use futures::FutureExt;
use futures::StreamExt;
use iroh_resolver::unixfs_builder;
use iroh_rpc_client::Client;
use iroh_rpc_client::StatusTable;
use iroh_util::{iroh_config_path, make_config};
#[cfg(feature = "testing")]
use mockall::automock;
use relative_path::RelativePathBuf;
use tokio::io::{AsyncRead, AsyncReadExt};

pub struct Iroh {
    client: Client,
}

pub enum OutType {
    Dir,
    Reader(Box<dyn AsyncRead + Unpin>),
    Symlink(PathBuf),
}

// Note: `#[async_trait]` is deliberately not in use for this trait, because it
// became very hard to express what we wanted once streams were involved.
// Instead we spell things out explicitly without magic.

#[cfg_attr(feature= "testing", automock(type P = MockP2p;))]
pub trait Api {
    type P: P2p;

    fn p2p(&self) -> Result<Self::P>;

    /// Produces a asynchronous stream of file descriptions
    /// Each description is a tuple of a relative path, and either a `Directory` or a `Reader`
    /// with the file contents.
    fn get_stream(
        &self,
        ipfs_path: &IpfsPath,
    ) -> LocalBoxStream<'_, Result<(RelativePathBuf, OutType)>>;

    fn add_file<'a>(&'a self, path: &'a Path, wrap: bool) -> LocalBoxFuture<'_, Result<Cid>>;
    fn add_dir(
        &self,
        path: &Path,
        wrap: bool,
    ) -> LocalBoxFuture<'_, Result<LocalBoxStream<'static, Result<AddEvent>>>>;
    fn add_symlink<'a>(&'a self, path: &'a Path, wrap: bool) -> LocalBoxFuture<'_, Result<Cid>>;

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
}

impl Api for Iroh {
    type P = ClientP2p;

    fn p2p(&self) -> Result<ClientP2p> {
        let p2p_client = self.client.try_p2p()?;
        Ok(ClientP2p::new(p2p_client.clone()))
    }

    fn get_stream(
        &self,
        ipfs_path: &IpfsPath,
    ) -> LocalBoxStream<'_, Result<(RelativePathBuf, OutType)>> {
        tracing::debug!("get {:?}", ipfs_path);
        let resolver = iroh_resolver::resolver::Resolver::new(self.client.clone());
        let results = resolver.resolve_recursive_with_paths(ipfs_path.clone());
        let sub_path = ipfs_path.to_relative_string();
        async_stream::try_stream! {
            tokio::pin!(results);
            while let Some(res) = results.next().await {
                let (relative_ipfs_path, out) = res?;
                let relative_path = RelativePathBuf::from_path(&relative_ipfs_path.to_relative_string())?;
                // TODO(faassen) this focusing in on sub-paths should really be handled in the resolver:
                // * it can be tested there far more easily than here (where currently it isn't)
                // * it makes sense to have an API "what does this resolve to" in the resolver
                // * the resolver may have opportunities for optimization we don't have
                if !relative_path.starts_with(&sub_path) {
                    continue;
                }
                let relative_path = relative_path.strip_prefix(&sub_path).expect("should be a prefix").to_owned();
                if out.is_dir() {
                    yield (relative_path, OutType::Dir);
                } else if out.is_symlink() {
                    let mut reader = out.pretty(resolver.clone(), Default::default(), iroh_resolver::resolver::ResponseClip::NoClip)?;
                    let mut target = String::new();
                    reader.read_to_string(&mut target).await?;
                    let target = PathBuf::from(target);
                    yield (relative_path, OutType::Symlink(target));
                } else {
                    let reader = out.pretty(resolver.clone(), Default::default(), iroh_resolver::resolver::ResponseClip::NoClip)?;
                    yield (relative_path, OutType::Reader(Box::new(reader)));
                }
            }
        }
        .boxed_local()
    }

    fn add_file<'a>(&'a self, path: &'a Path, wrap: bool) -> LocalBoxFuture<'_, Result<Cid>> {
        async move {
            let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
                client: self.client.clone(),
            };
            unixfs_builder::add_file(Some(providing_client), path, wrap).await
        }
        .boxed_local()
    }

    fn add_dir(
        &self,
        path: &Path,
        wrap: bool,
    ) -> LocalBoxFuture<'_, Result<LocalBoxStream<'static, Result<AddEvent>>>> {
        let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
            client: self.client.clone(),
        };
        let path = path.to_path_buf();
        async move {
            unixfs_builder::add_dir(Some(providing_client), &path, wrap)
                .await
                .map(|s| s.boxed_local())
        }
        .boxed_local()
    }

    fn add_symlink<'a>(&'a self, path: &'a Path, wrap: bool) -> LocalBoxFuture<'_, Result<Cid>> {
        async move {
            let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
                client: self.client.clone(),
            };
            unixfs_builder::add_symlink(Some(providing_client), path, wrap).await
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
