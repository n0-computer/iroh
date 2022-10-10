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
    use std::collections::HashSet;
    use std::net::SocketAddr;

    use super::*;
    use cid::Cid;
    use futures::{StreamExt, TryStreamExt};
    use iroh_resolver::unixfs::UnixfsNode;
    use iroh_resolver::unixfs_builder::{DirectoryBuilder, FileBuilder};
    use iroh_rpc_client::Client as RpcClient;
    use iroh_rpc_client::Config as RpcClientConfig;
    use iroh_rpc_types::store::StoreClientAddr;
    use iroh_rpc_types::Addr;
    use std::io;
    use tokio_util::io::StreamReader;

    use crate::config::Config;

    async fn spawn_gateway(
        config: Arc<Config>,
    ) -> (SocketAddr, RpcClient, tokio::task::JoinHandle<()>) {
        let rpc_addr = "grpc://0.0.0.0:0".parse().unwrap();
        let rpc_client = RpcClient::new(config.rpc_client().clone()).await.unwrap();
        let core = Core::new(config, rpc_addr, Arc::new(None), rpc_client.clone())
            .await
            .unwrap();
        let server = core.server();
        let addr = server.local_addr();
        let core_task = tokio::spawn(async move {
            server.await.unwrap();
        });
        (addr, rpc_client, core_task)
    }

    async fn spawn_store() -> (StoreClientAddr, tokio::task::JoinHandle<()>) {
        let (server_addr, client_addr) = Addr::new_mem();
        let store_dir = tempfile::tempdir().unwrap();
        let config = iroh_store::Config {
            path: store_dir.path().join("db"),
            rpc_client: RpcClientConfig::default(),
            metrics: iroh_metrics::config::Config::default(),
        };
        let store = iroh_store::Store::create(config).await.unwrap();
        let task =
            tokio::spawn(async move { iroh_store::rpc::new(server_addr, store).await.unwrap() });
        (client_addr, task)
    }

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

        let (addr, _rpc_client, core_task) = spawn_gateway(Arc::new(config)).await;

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

    #[tokio::test]
    async fn fetch_car_recursive() {
        let (store_client_addr, store_task) = spawn_store().await;
        let mut config = Config::new(
            false,
            false,
            false,
            0,
            RpcClientConfig {
                gateway_addr: None,
                p2p_addr: None,
                store_addr: Some(store_client_addr),
            },
        );
        config.set_default_headers();

        let (addr, rpc_client, core_task) = spawn_gateway(Arc::new(config)).await;

        let dir = "demo";
        let files = [
            ("hello.txt".to_string(), b"ola".to_vec()),
            ("world.txt".to_string(), b"mundo".to_vec()),
        ];

        // add a directory with two files to the store.
        let (root_cid, all_cids) = {
            let store = rpc_client.try_store().unwrap();
            let mut cids = vec![];
            let mut dir_builder = DirectoryBuilder::new();
            dir_builder.name(dir);
            for (name, content) in &files {
                let mut file = FileBuilder::new();
                file.name(name).content_bytes(content.clone());
                dir_builder.add_file(file.build().await.unwrap());
            }

            let root_dir = dir_builder.build().unwrap();
            let mut parts = root_dir.encode();
            while let Some(part) = parts.next().await {
                let (cid, bytes) = part.unwrap();
                cids.push(cid);
                store.put(cid, bytes, vec![]).await.unwrap();
            }
            (*cids.last().unwrap(), cids)
        };

        // request the root cid as a recursive car
        let res = {
            let client = hyper::Client::new();
            let uri = hyper::Uri::builder()
                .scheme("http")
                .authority(format!("localhost:{}", addr.port()))
                .path_and_query(format!("/ipfs/{}?recursive=true", root_cid))
                .build()
                .unwrap();
            let req = hyper::Request::builder()
                .method("GET")
                .header("accept", "application/vnd.ipld.car")
                .uri(uri)
                .body(hyper::Body::empty())
                .unwrap();
            client.request(req).await.unwrap()
        };

        assert_eq!(http::StatusCode::OK, res.status());

        // read the response body into a car reader and map the entries
        // to UnixFS nodes
        let body = StreamReader::new(
            res.into_body()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string())),
        );
        let car_reader = iroh_car::CarReader::new(body).await.unwrap();
        let (nodes, cids): (Vec<UnixfsNode>, Vec<Cid>) = car_reader
            .stream()
            .map(|res| res.unwrap())
            .map(|(cid, bytes)| (UnixfsNode::decode(&cid, bytes.into()).unwrap(), cid))
            .unzip()
            .await;

        // match cids and content
        assert_eq!(cids.len(), all_cids.len());
        assert_eq!(
            HashSet::<_>::from_iter(cids.iter()),
            HashSet::from_iter(all_cids.iter())
        );
        assert_eq!(cids[0], root_cid);
        assert_eq!(nodes.len(), files.len() + 1);
        assert!(nodes[0].is_dir());
        assert_eq!(
            nodes[0]
                .links()
                .map(|link| link.unwrap().name.unwrap().to_string())
                .collect::<Vec<_>>(),
            files
                .iter()
                .map(|(name, _content)| name.clone())
                .collect::<Vec<_>>()
        );

        for (i, node) in nodes[1..].iter().enumerate() {
            assert_eq!(node, &UnixfsNode::Raw(files[i].1.clone().into()));
        }

        core_task.abort();
        core_task.await.unwrap_err();
        store_task.abort();
        store_task.await.unwrap_err();
    }
}
