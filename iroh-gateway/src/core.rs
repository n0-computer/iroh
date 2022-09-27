use axum::Router;
use iroh_resolver::resolver::ContentLoader;
use iroh_rpc_types::gateway::GatewayServerAddr;

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
pub struct Core<T: ContentLoader> {
    state: Arc<State<T>>,
}

#[derive(Debug, Clone)]
pub struct State<T: ContentLoader> {
    pub config: Arc<dyn StateConfig>,
    pub client: Client<T>,
    pub handlebars: HashMap<String, String>,
    pub bad_bits: Arc<Option<RwLock<BadBits>>>,
}

impl<T: ContentLoader + std::marker::Unpin> Core<T> {
    pub async fn new(
        config: Arc<dyn StateConfig>,
        rpc_addr: GatewayServerAddr,
        bad_bits: Arc<Option<RwLock<BadBits>>>,
        content_loader: T,
    ) -> anyhow::Result<Self> {
        tokio::spawn(async move {
            if let Err(err) = rpc::new(rpc_addr, Gateway::default()).await {
                tracing::error!("Failed to run gateway rpc handler: {}", err);
            }
        });
        let mut templates = HashMap::new();
        templates.insert("dir_list".to_string(), templates::DIR_LIST.to_string());
        templates.insert("not_found".to_string(), templates::NOT_FOUND.to_string());
        let client = Client::<T>::new(&content_loader);

        Ok(Self {
            state: Arc::new(State {
                config,
                client,
                handlebars: templates,
                bad_bits,
            }),
        })
    }

    pub async fn new_with_state(
        rpc_addr: GatewayServerAddr,
        state: Arc<State<T>>,
    ) -> anyhow::Result<Self> {
        tokio::spawn(async move {
            if let Err(err) = rpc::new(rpc_addr, Gateway::default()).await {
                tracing::error!("Failed to run gateway rpc handler: {}", err);
            }
        });
        Ok(Self { state })
    }

    pub async fn make_state(
        config: Arc<dyn StateConfig>,
        bad_bits: Arc<Option<RwLock<BadBits>>>,
        content_loader: T,
    ) -> anyhow::Result<Arc<State<T>>> {
        let mut templates = HashMap::new();
        templates.insert("dir_list".to_string(), templates::DIR_LIST.to_string());
        templates.insert("not_found".to_string(), templates::NOT_FOUND.to_string());
        let client = Client::new(&content_loader);
        Ok(Arc::new(State {
            config,
            client,
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
    use iroh_rpc_client::Client as RpcClient;
    use iroh_rpc_client::Config as RpcClientConfig;

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

        let rpc_addr = "grpc://0.0.0.0:0".parse().unwrap();
        let content_loader = RpcClient::new(config.rpc_client().clone()).await.unwrap();
        let handler = Core::new(Arc::new(config), rpc_addr, Arc::new(None), content_loader)
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
