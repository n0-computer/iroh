use std::{sync::Arc};
use anyhow::{anyhow, Result};
use iroh_api::Api;
use iroh_metrics::MetricsHandle;
use crate::{
  config::Config,
  mem_store,
  mem_p2p
};
use iroh_rpc_client::Client as RpcClient;
use iroh_gateway::{bad_bits::BadBits, metrics};

#[cfg(feature = "uds-gateway")]
use iroh_one::uds;
use iroh_resolver::racing::RacingLoader;
use iroh_rpc_types::Addr;
#[cfg(feature = "uds-gateway")]
use tempdir::TempDir;
use tokio::sync::RwLock;
use tokio::task;


pub struct Core<'a> {
  config: &'a mut Config,

  core_task: Option<task::JoinHandle<()>>,
  p2p_rpc: Option<task::JoinHandle<()>>,
  store_rpc: Option<task::JoinHandle<()>>,
  metrics_handle: Option<MetricsHandle>,
  #[cfg(feature = "uds-gateway")]
  uds_service_task: Option<JoinHandle<()>>,
}

impl <'a>Core<'a> {
  pub fn new(config: &'a mut Config) -> Result<Self> {
    Ok(Core{
      config,
      core_task: None,
      metrics_handle: None,
      #[cfg(feature = "uds-gateway")]
      uds_service_task: None,
      p2p_rpc: None,
      store_rpc: None,
    })
  }

  pub async fn start(&mut self) -> Result<()> {

    {
      let (store_recv, store_sender) = Addr::new_mem();
      self.config.rpc_client.store_addr = Some(store_sender);
      let rpc = mem_store::start(store_recv, self.config.clone().store).await?;
      self.store_rpc = Some(rpc);

      let (p2p_recv, p2p_sender) = Addr::new_mem();
      self.config.rpc_client.p2p_addr = Some(p2p_sender);
      let rpc = mem_p2p::start(p2p_recv, self.config.clone().p2p).await?;
      self.p2p_rpc = Some(rpc);
    }

    self.config.synchronize_subconfigs();
    self.config.metrics = metrics::metrics_config_with_compile_time_info(self.config.metrics.clone());
    println!("{:#?}", self.config);

    let metrics_config = self.config.metrics.clone();

    let gateway_rpc_addr = self.config
        .gateway
        .server_rpc_addr()?
        .ok_or_else(|| anyhow!("missing gateway rpc addr"))?;

    let bad_bits = match self.config.gateway.use_denylist {
      true => Arc::new(Some(RwLock::new(BadBits::new()))),
      false => Arc::new(None),
    };

    let content_loader = RacingLoader::new(
        RpcClient::new(self.config.rpc_client.clone()).await?,
        self.config.gateway.http_resolvers.clone().unwrap_or_default(),
    );
    let shared_state = iroh_gateway::core::Core::make_state(
        Arc::new(self.config.clone()),
        Arc::clone(&bad_bits),
        content_loader,
    )
    .await?;

    let handler = iroh_gateway::core::Core::new_with_state(gateway_rpc_addr, Arc::clone(&shared_state)).await?;

    let metrics_handle = iroh_metrics::MetricsHandle::new(metrics_config)
        .await
        .expect("failed to initialize metrics");
    self.metrics_handle = Some(metrics_handle);
    let server = handler.server();
    self.core_task = Some(tokio::spawn(async move {
        server.await.unwrap();
    }));

    #[cfg(feature = "uds-gateway")]
    {
      self.uds_server_task = {
          let mut path = TempDir::new("iroh")?.path().join("ipfsd.http");
          if let Some(uds_path) = config.gateway_uds_path {
              path = uds_path;
          } else {
              // Create the parent path when using the default value since it's likely
              // it won't exist yet.
              if let Some(parent) = path.parent() {
                  let _ = std::fs::create_dir_all(&parent);
              }
          }

          tokio::spawn(async move {
              if let Some(uds_server) = uds::uds_server(shared_state, path) {
                  if let Err(err) = uds_server.await {
                      tracing::error!("Failure in http uds handler: {}", err);
                  }
              }
          })
      };
    }

    Ok(())
  }

  pub async fn api(&self) -> Result<Api> {
    let cfg = iroh_api::config::Config{
      rpc_client: self.config.rpc_client.clone(),
      metrics: self.config.metrics.clone(),
    };
    Api::new(cfg).await
  }

  pub fn stop(&mut self) -> Result<()> {
    if let Some(store) = &self.store_rpc {
      store.abort();
    }
    if let Some(p2p) = &self.p2p_rpc {
      p2p.abort();
    }
    #[cfg(feature = "uds-gateway")]
    if let Some(uds) = &self.uds_server_task {
      uds.abort();
    }
    if let Some(core_task) = &self.core_task {
      core_task.abort();
    }
    if let Some(metrics) = &self.metrics_handle {
      metrics.shutdown();
    }
    Ok(())
  }
}