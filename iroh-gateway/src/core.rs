use axum::Router;
use iroh_metrics::gateway::Metrics;
use iroh_rpc_client::Client as RpcClient;
use iroh_rpc_types::gateway::GatewayServerAddr;
use prometheus_client::registry::Registry;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use crate::{
    bad_bits::BadBits,
    client::Client,
    handlers::{get_app_routes, StateConfig},
    rpc,
    rpc::Gateway,
    templates,
};

#[derive(Debug, Clone)]
pub struct Core {
    state: Arc<State>,
}

#[derive(Debug, Clone)]
pub struct State {
    pub config: Arc<dyn StateConfig>,
    pub client: Client,
    pub handlebars: HashMap<String, String>,
    pub metrics: Metrics,
    pub bad_bits: Arc<Option<RwLock<BadBits>>>,
}

impl Core {
    pub async fn new(
        config: Arc<dyn StateConfig>,
        rpc_addr: GatewayServerAddr,
        metrics: Metrics,
        registry: &mut Registry,
        bad_bits: Arc<Option<RwLock<BadBits>>>,
    ) -> anyhow::Result<Self> {
        tokio::spawn(async move {
            // TODO: handle error
            rpc::new(rpc_addr, Gateway::default()).await
        });
        let rpc_client = RpcClient::new(config.rpc_client()).await?;
        let mut templates = HashMap::new();
        templates.insert("dir_list".to_string(), templates::DIR_LIST.to_string());
        templates.insert("not_found".to_string(), templates::NOT_FOUND.to_string());
        let client = Client::new(&rpc_client, registry);

        Ok(Self {
            state: Arc::new(State {
                config,
                client,
                metrics,
                handlebars: templates,
                bad_bits,
            }),
        })
    }

    pub async fn new_with_state(
        rpc_addr: GatewayServerAddr,
        state: Arc<State>,
    ) -> anyhow::Result<Self> {
        tokio::spawn(async move {
            // TODO: handle error
            rpc::new(rpc_addr, Gateway::default()).await
        });
        Ok(Self { state })
    }

    pub async fn make_state(
        config: Arc<dyn StateConfig>,
        metrics: Metrics,
        registry: &mut Registry,
        bad_bits: Arc<Option<RwLock<BadBits>>>,
    ) -> anyhow::Result<Arc<State>> {
        let rpc_client = RpcClient::new(config.rpc_client()).await?;
        let mut templates = HashMap::new();
        templates.insert("dir_list".to_string(), templates::DIR_LIST.to_string());
        templates.insert("not_found".to_string(), templates::NOT_FOUND.to_string());
        let client = Client::new(&rpc_client, registry);
        Ok(Arc::new(State {
            config,
            client,
            metrics,
            handlebars: templates,
            bad_bits,
        }))
    }

    pub fn server(
        self,
    ) -> axum::Server<hyper::server::conn::AddrIncoming, axum::routing::IntoMakeService<Router>>
    {
        let app = get_app_routes(&self.state);

        // todo(arqu): make configurable
        let addr = format!("0.0.0.0:{}", self.state.config.port());

        axum::Server::bind(&addr.parse().unwrap())
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve(app.into_make_service())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use iroh_rpc_client::Config as RpcClientConfig;
    use prometheus_client::registry::Registry;

    #[tokio::test]
    async fn gateway_health() {
        let mut config = Config::new(
            false,
            false,
            false,
            0,
            RpcClientConfig {
                gateway_addr: None,
                p2p_addr: None,
                store_addr: None,
            },
        );
        config.set_default_headers();

        let mut prom_registry = Registry::default();
        let gw_metrics = Metrics::new(&mut prom_registry);
        let rpc_addr = "grpc://0.0.0.0:0".parse().unwrap();
        let handler = Core::new(
            Arc::new(config),
            rpc_addr,
            gw_metrics,
            &mut prom_registry,
            Arc::new(None),
        )
        .await
        .unwrap();
        let server = handler.server();
        let addr = server.local_addr();
        let core_task = tokio::spawn(async move {
            server.await.unwrap();
        });

        let uri = hyper::Uri::builder()
            .scheme("http")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query("/health")
            .build()
            .unwrap();
        let client = hyper::Client::new();
        let res = client.get(uri).await.unwrap();

        assert_eq!(http::StatusCode::OK, res.status());
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        assert_eq!(b"OK", &body[..]);
        core_task.abort();
        core_task.await.unwrap_err();
    }
}
