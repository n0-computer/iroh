use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::config::{Config, CONFIG_FILE_NAME, ENV_PREFIX};
use crate::P2pApi;
use crate::{AddEvent, IpfsPath};
use anyhow::{ensure, Context, Result};
use cid::Cid;
use futures::stream::LocalBoxStream;
use futures::{StreamExt, TryStreamExt};
use iroh_resolver::content_loader::{FullLoader, FullLoaderConfig};
use iroh_resolver::resolver::Resolver;
use iroh_resolver::unixfs_builder::{self, ChunkerConfig};
use iroh_rpc_client::Client;
use iroh_rpc_client::StatusTable;
use iroh_util::{iroh_config_path, make_config};
#[cfg(feature = "testing")]
use mockall::automock;
use relative_path::RelativePathBuf;
use tokio::io::{AsyncRead, AsyncReadExt};

/// API to interact with an iroh system.
///
/// This provides an API to use the iroh system consisting of several services working
/// together.  It offers both a higher level API as well as some lower-level APIs.
///
/// Unless working on iroh directly this should probably be constructed via the `iroh-embed`
/// crate rather then directly.
#[derive(Debug, Clone)]
pub struct Api {
    client: Client,
    resolver: Resolver<FullLoader>,
}

pub enum OutType {
    Dir,
    Reader(Box<dyn AsyncRead + Unpin>),
    Symlink(PathBuf),
}

impl fmt::Debug for OutType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dir => write!(f, "Dir"),
            Self::Reader(_) => write!(f, "Reader(impl AsyncRead + Unpin>)"),
            Self::Symlink(arg0) => f.debug_tuple("Symlink").field(arg0).finish(),
        }
    }
}

#[cfg_attr(feature = "testing", allow(dead_code), automock)]
impl Api {
    /// Creates a new instance from the iroh configuration.
    ///
    /// This loads configuration from an optional configuration file and environment
    /// variables.
    // The lifetime is needed for mocking.
    #[allow(clippy::needless_lifetimes)]
    pub async fn from_env<'a>(
        config_path: Option<&'a Path>,
        overrides_map: HashMap<String, String>,
    ) -> Result<Self> {
        let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
        let sources = [Some(cfg_path.as_path()), config_path];
        let config = make_config(
            // default
            Config::default(),
            // potential config files
            &sources,
            // env var prefix for this config
            ENV_PREFIX,
            // map of present command line arguments
            overrides_map,
        )?;
        Self::new(config).await
    }

    /// Creates a new instance from the provided configuration.
    pub async fn new(config: Config) -> Result<Self> {
        let client = Client::new(config.rpc_client).await?;
        let content_loader = FullLoader::new(
            client.clone(),
            FullLoaderConfig {
                http_gateways: config
                    .http_resolvers
                    .iter()
                    .flatten()
                    .map(|u| u.parse())
                    .collect::<Result<_>>()
                    .context("invalid gateway url")?,
                indexer: config.indexer_endpoint,
            },
        )?;
        let resolver = Resolver::new(content_loader);

        Ok(Self { client, resolver })
    }

    /// Announces to the DHT that this node can offer the given [`Cid`].
    ///
    /// This publishes a provider record for the [`Cid`] to the DHT, establishing the local
    /// node as provider for the [`Cid`].
    pub async fn provide(&self, cid: Cid) -> Result<()> {
        self.client.try_p2p()?.start_providing(&cid).await
    }

    pub fn p2p(&self) -> Result<P2pApi> {
        let p2p_client = self.client.try_p2p()?;
        Ok(P2pApi::new(p2p_client))
    }

    /// High level get, equivalent of CLI `iroh get`.
    ///
    /// Returns a stream of items, where items can be either blobs or UnixFs components.
    /// Each blob will be a full object, a file in case of UnixFs, and not raw chunks.
    pub fn get(
        &self,
        ipfs_path: &IpfsPath,
    ) -> Result<LocalBoxStream<'static, Result<(RelativePathBuf, OutType)>>> {
        ensure!(
            ipfs_path.cid().is_some(),
            "IPFS path does not refer to a CID"
        );

        tracing::debug!("get {:?}", ipfs_path);
        let resolver = self.resolver.clone();
        let results = resolver.resolve_recursive_with_paths(ipfs_path.clone());
        let sub_path = ipfs_path.to_relative_string();

        let stream = async_stream::try_stream! {
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
        };

        Ok(stream.boxed_local())
    }

    pub async fn add_file(
        &self,
        path: &Path,
        wrap: bool,
        chunker: ChunkerConfig,
    ) -> Result<LocalBoxStream<'static, Result<AddEvent>>> {
        let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
            client: self.client.clone(),
        };
        let path = path.to_path_buf();
        let stream = unixfs_builder::add_file(
            Some(providing_client),
            &path,
            iroh_resolver::unixfs_builder::Config { wrap, chunker },
        )
        .await?;

        Ok(stream.boxed_local())
    }

    pub async fn add_dir(
        &self,
        path: &Path,
        wrap: bool,
        chunker: ChunkerConfig,
    ) -> Result<LocalBoxStream<'static, Result<AddEvent>>> {
        let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
            client: self.client.clone(),
        };
        let path = path.to_path_buf();
        let stream = unixfs_builder::add_dir(
            Some(providing_client),
            &path,
            iroh_resolver::unixfs_builder::Config { wrap, chunker },
        )
        .await?;

        Ok(stream.boxed_local())
    }

    pub async fn add_symlink(
        &self,
        path: &Path,
        wrap: bool,
    ) -> Result<LocalBoxStream<'static, Result<AddEvent>>> {
        let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
            client: self.client.clone(),
        };
        let path = path.to_path_buf();
        let stream = unixfs_builder::add_symlink(Some(providing_client), &path, wrap).await?;

        Ok(stream.boxed_local())
    }

    pub async fn check(&self) -> StatusTable {
        self.client.check().await
    }

    pub async fn watch(&self) -> LocalBoxStream<'static, iroh_rpc_client::StatusTable> {
        self.client.clone().watch().await.boxed_local()
    }

    pub async fn add_stream(
        &self,
        path: &Path,
        wrap: bool,
        chunker: ChunkerConfig,
    ) -> Result<LocalBoxStream<'static, Result<AddEvent>>> {
        if path.is_dir() {
            self.add_dir(path, wrap, chunker).await
        } else if path.is_symlink() {
            self.add_symlink(path, wrap).await
        } else if path.is_file() {
            self.add_file(path, wrap, chunker).await
        } else {
            anyhow::bail!("can only add files or directories")
        }
    }

    pub async fn add(&self, path: &Path, wrap: bool, chunker: ChunkerConfig) -> Result<Cid> {
        let add_events = self.add_stream(path, wrap, chunker).await?;

        add_events
            .try_fold(None, |_acc, add_event| async move {
                match add_event {
                    AddEvent::ProgressDelta { cid, .. } => Ok(Some(cid)),
                }
            })
            .await?
            .context("No cid found")
    }
}
