use crate::{rpc, rpc::Gateway, uds};
use axum::{Router, Server};
use iroh_gateway::{
    bad_bits::BadBits,
    client::Client,
    core::State,
    handlers::{get_app_routes, StateConfig},
    templates,
};
use iroh_metrics::gateway::Metrics;
use iroh_rpc_client::Client as RpcClient;
use iroh_rpc_types::gateway::GatewayServerAddr;
use prometheus_client::registry::Registry;
use std::{collections::HashMap, sync::Arc};
use tokio::{net::UnixListener, sync::RwLock};

#[derive(Debug)]
pub struct Core {
    state: Arc<State>,
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
            state: Arc::new(iroh_gateway::core::State {
                config,
                client,
                metrics,
                handlebars: templates,
                bad_bits,
            }),
        })
    }

    pub fn http_server(
        &self,
    ) -> Server<hyper::server::conn::AddrIncoming, axum::routing::IntoMakeService<Router>> {
        let app = get_app_routes(&self.state);
        // todo(arqu): make configurable
        let addr = format!("0.0.0.0:{}", self.state.config.port());

        Server::bind(&addr.parse().unwrap())
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve(app.into_make_service())
    }

    pub fn uds_server(
        &self,
    ) -> Server<
        uds::ServerAccept,
        axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, uds::UdsConnectInfo>,
    > {
        #[cfg(target_os = "android")]
        let path = "/dev/socket/ipfsd.http".to_owned();

        #[cfg(not(target_os = "android"))]
        let path = format!("{}", std::env::temp_dir().join("ipfsd.http").display());

        let _ = std::fs::remove_file(&path);
        let uds = UnixListener::bind(&path).unwrap();
        println!("Binding to UDS at {}", path);
        let app = get_app_routes(&self.state);
        Server::builder(uds::ServerAccept { uds })
            .serve(app.into_make_service_with_connect_info::<uds::UdsConnectInfo>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, GatewayConfig};
    use prometheus_client::registry::Registry;

    #[tokio::test]
    async fn gateway_health() {
        let mut gateway = GatewayConfig::default();
        gateway.set_default_headers();
        let config = Config {
            gateway,
            ..Default::default()
        };

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
        let server = handler.http_server();
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
