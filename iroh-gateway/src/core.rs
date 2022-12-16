use std::{collections::HashMap, sync::Arc};

use axum::Router;
use iroh_resolver::dns_resolver::Config as DnsResolverConfig;
use iroh_rpc_types::gateway::GatewayAddr;
use iroh_unixfs::content_loader::ContentLoader;
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

impl<T: ContentLoader + Unpin> Core<T> {
    pub async fn new(
        config: Arc<dyn StateConfig>,
        rpc_addr: GatewayAddr,
        bad_bits: Arc<Option<RwLock<BadBits>>>,
        content_loader: T,
        dns_resolver_config: DnsResolverConfig,
    ) -> anyhow::Result<Self> {
        tokio::spawn(async move {
            if let Err(err) = rpc::new(rpc_addr, Gateway::default()).await {
                tracing::error!("Failed to run gateway rpc handler: {}", err);
            }
        });
        let mut templates = HashMap::new();
        templates.insert(
            "dir_list".to_string(),
            templates::DIR_LIST_TEMPLATE.to_string(),
        );
        templates.insert(
            "not_found".to_string(),
            templates::NOT_FOUND_TEMPLATE.to_string(),
        );
        let client = Client::<T>::new(&content_loader, dns_resolver_config);

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
        rpc_addr: GatewayAddr,
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
        dns_resolver_config: DnsResolverConfig,
    ) -> anyhow::Result<Arc<State<T>>> {
        let mut templates = HashMap::new();
        templates.insert(
            "dir_list".to_string(),
            templates::DIR_LIST_TEMPLATE.to_string(),
        );
        templates.insert(
            "not_found".to_string(),
            templates::NOT_FOUND_TEMPLATE.to_string(),
        );
        let client = Client::new(&content_loader, dns_resolver_config);
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
    use axum::response::Response;
    use cid::Cid;
    use futures::{StreamExt, TryStreamExt};
    use hyper::Body;
    use iroh_rpc_client::Client as RpcClient;
    use iroh_rpc_client::Config as RpcClientConfig;
    use iroh_rpc_types::store::StoreAddr;
    use iroh_rpc_types::Addr;
    use iroh_unixfs::builder::{DirectoryBuilder, FileBuilder};
    use iroh_unixfs::content_loader::{FullLoader, FullLoaderConfig};
    use iroh_unixfs::unixfs::UnixfsNode;
    use std::io;
    use tokio_util::io::StreamReader;

    use crate::config::Config;

    struct TestSetup {
        gateway_addr: SocketAddr,
        root_cid: Cid,
        file_cids: Vec<Cid>,
        core_task: tokio::task::JoinHandle<()>,
        store_task: tokio::task::JoinHandle<()>,
        files: Vec<(String, Vec<u8>)>,
    }

    impl TestSetup {
        pub async fn shutdown(self) {
            self.core_task.abort();
            self.store_task.abort();
            self.store_task.await.ok();
        }
    }

    async fn spawn_gateway(
        config: Arc<Config>,
    ) -> (SocketAddr, RpcClient, tokio::task::JoinHandle<()>) {
        let rpc_addr = "irpc://0.0.0.0:0".parse().unwrap();
        let rpc_client = RpcClient::new(config.rpc_client().clone()).await.unwrap();
        let loader_config = FullLoaderConfig {
            http_gateways: config
                .http_resolvers
                .iter()
                .flatten()
                .map(|u| u.parse().unwrap())
                .collect(),
            indexer: config.indexer_endpoint.as_ref().map(|p| p.parse().unwrap()),
        };
        let content_loader =
            FullLoader::new(rpc_client.clone(), loader_config).expect("invalid config");
        let core = Core::new(
            config,
            rpc_addr,
            Arc::new(None),
            content_loader,
            DnsResolverConfig::default(),
        )
        .await
        .unwrap();
        let server = core.server();
        let addr = server.local_addr();
        let core_task = tokio::spawn(async move {
            server.await.unwrap();
        });
        (addr, rpc_client, core_task)
    }

    async fn spawn_store() -> (StoreAddr, tokio::task::JoinHandle<()>) {
        let server_addr = Addr::new_mem();
        let client_addr = server_addr.clone();
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

    async fn put_directory_with_files(
        rpc_client: &RpcClient,
        dir: &str,
        files: &[(String, Vec<u8>)],
    ) -> (Cid, Vec<Cid>) {
        let store = rpc_client.try_store().unwrap();
        let mut cids = vec![];
        let mut dir_builder = DirectoryBuilder::new().name(dir);
        for (name, content) in files {
            let file = FileBuilder::new()
                .name(name)
                .content_bytes(content.clone())
                .build()
                .await
                .unwrap();
            dir_builder = dir_builder.add_file(file);
        }

        let root_dir = dir_builder.build().await.unwrap();
        let mut parts = root_dir.encode();
        while let Some(part) = parts.next().await {
            let (cid, bytes, links) = part.unwrap().into_parts();
            cids.push(cid);
            store.put(cid, bytes, links).await.unwrap();
        }
        (*cids.last().unwrap(), cids)
    }

    async fn do_request(
        method: &str,
        authority: &str,
        path_and_query: &str,
        headers: Option<&[(&str, &str)]>,
    ) -> Response<Body> {
        let client = hyper::Client::new();
        let uri = hyper::Uri::builder()
            .scheme("http")
            .authority(authority)
            .path_and_query(path_and_query)
            .build()
            .unwrap();
        let mut req = hyper::Request::builder().method(method).uri(uri);
        if let Some(headers) = headers {
            for header in headers {
                req = req.header(header.0, header.1);
            }
        }
        client
            .request(req.body(hyper::Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn setup_test(redirect_to_subdomains: bool) -> TestSetup {
        let (store_client_addr, store_task) = spawn_store().await;
        let mut config = Config::new(
            0,
            RpcClientConfig {
                gateway_addr: None,
                p2p_addr: None,
                store_addr: Some(store_client_addr),
                channels: Some(1),
            },
        );
        config.set_default_headers();
        config.redirect_to_subdomain = redirect_to_subdomains;
        let (gateway_addr, rpc_client, core_task) = spawn_gateway(Arc::new(config)).await;
        let dir = "demo";
        let files = vec![
            ("hello.txt".to_string(), b"ola".to_vec()),
            ("world.txt".to_string(), b"mundo".to_vec()),
        ];
        let (root_cid, file_cids) = put_directory_with_files(&rpc_client, dir, &files).await;

        TestSetup {
            gateway_addr,
            root_cid,
            file_cids,
            core_task,
            store_task,
            files,
        }
    }

    #[tokio::test]
    async fn gateway_health() {
        let mut config = Config::new(
            0,
            RpcClientConfig {
                gateway_addr: None,
                p2p_addr: None,
                store_addr: None,
                channels: Some(1),
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

    // TODO(b5) - refactor to return anyhow::Result<()>
    #[tokio::test]
    async fn test_fetch_car_recursive() {
        let test_setup = setup_test(false).await;

        // request the root cid as a recursive car
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            &format!("/ipfs/{}?recursive=true", test_setup.root_cid),
            Some(&[("accept", "application/vnd.ipld.car")]),
        )
        .await;
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
        assert_eq!(cids.len(), test_setup.file_cids.len());
        assert_eq!(
            HashSet::<_>::from_iter(cids.iter()),
            HashSet::from_iter(test_setup.file_cids.iter())
        );
        assert_eq!(cids[0], test_setup.root_cid);
        assert_eq!(nodes.len(), test_setup.files.len() + 1);
        assert!(nodes[0].is_dir());
        assert_eq!(
            nodes[0]
                .links()
                .map(|link| link.unwrap().name.unwrap().to_string())
                .collect::<Vec<_>>(),
            test_setup
                .files
                .iter()
                .map(|(name, _content)| name.to_string())
                .collect::<Vec<_>>()
        );

        for (i, node) in nodes[1..].iter().enumerate() {
            assert_eq!(node, &UnixfsNode::Raw(test_setup.files[i].1.clone().into()));
        }
        test_setup.shutdown().await
    }

    #[tokio::test]
    async fn test_head_request_to_file() {
        let test_setup = setup_test(false).await;

        // request the root cid as a recursive car
        let res = do_request(
            "HEAD",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            &format!("/ipfs/{}/{}", test_setup.root_cid, "world.txt"),
            None,
        )
        .await;

        assert_eq!(http::StatusCode::OK, res.status());
        assert!(res.headers().get("content-length").is_some());
        assert_eq!(res.headers().get("content-length").unwrap(), "5");

        let (body, _) = res.into_body().into_future().await;
        assert!(body.is_none());

        test_setup.shutdown().await
    }

    #[tokio::test]
    async fn test_gateway_requests() {
        let test_setup = setup_test(false).await;

        // request the root cid as a recursive car
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            "/?recursive=true",
            Some(&[
                ("accept", "application/vnd.ipld.car"),
                ("host", &format!("{}.ipfs.localhost", test_setup.root_cid)),
            ]),
        )
        .await;

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
        assert_eq!(cids.len(), test_setup.file_cids.len());
        assert_eq!(
            HashSet::<_>::from_iter(cids.iter()),
            HashSet::from_iter(test_setup.file_cids.iter())
        );
        assert_eq!(cids[0], test_setup.root_cid);
        assert_eq!(nodes.len(), test_setup.files.len() + 1);
        assert!(nodes[0].is_dir());
        assert_eq!(
            nodes[0]
                .links()
                .map(|link| link.unwrap().name.unwrap().to_string())
                .collect::<Vec<_>>(),
            test_setup
                .files
                .iter()
                .map(|(name, _content)| name.to_string())
                .collect::<Vec<_>>()
        );

        for (i, node) in nodes[1..].iter().enumerate() {
            assert_eq!(node, &UnixfsNode::Raw(test_setup.files[i].1.clone().into()));
        }

        test_setup.shutdown().await
    }

    #[tokio::test]
    async fn test_gateway_redirection() {
        let test_setup = setup_test(true).await;

        // Usual request
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            &format!("/ipfs/{}/{}", test_setup.root_cid, "world.txt"),
            None,
        )
        .await;

        assert_eq!(http::StatusCode::MOVED_PERMANENTLY, res.status());
        assert_eq!(
            format!(
                "http://{}.ipfs.localhost:{}/world.txt",
                test_setup.root_cid,
                test_setup.gateway_addr.port()
            ),
            res.headers().get("Location").unwrap().to_str().unwrap(),
        );

        // No trailing slash
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            &format!("/ipfs/{}", test_setup.root_cid),
            None,
        )
        .await;

        assert_eq!(http::StatusCode::MOVED_PERMANENTLY, res.status());
        assert_eq!(
            format!(
                "http://{}.ipfs.localhost:{}/",
                test_setup.root_cid,
                test_setup.gateway_addr.port()
            ),
            res.headers().get("Location").unwrap().to_str().unwrap()
        );

        // Trailing slash
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            &format!("/ipfs/{}/", test_setup.root_cid),
            None,
        )
        .await;

        assert_eq!(http::StatusCode::MOVED_PERMANENTLY, res.status());
        assert_eq!(
            format!(
                "http://{}.ipfs.localhost:{}/",
                test_setup.root_cid,
                test_setup.gateway_addr.port()
            ),
            res.headers().get("Location").unwrap().to_str().unwrap()
        );

        // IPNS
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            "/ipns/k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8",
            None,
        )
        .await;

        assert_eq!(http::StatusCode::MOVED_PERMANENTLY, res.status());
        assert_eq!(
            format!(
                "http://k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8.ipns.localhost:{}/",
                test_setup.gateway_addr.port()
            ),
            res.headers().get("Location").unwrap().to_str().unwrap()
        );

        // Test that IPNS records are recoded to base36
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            "/ipns/bafyreihyrpefhacm6kkp4ql6j6udakdit7g3dmkzfriqfykhjw6cad5lrm",
            None,
        )
        .await;

        assert_eq!(http::StatusCode::MOVED_PERMANENTLY, res.status());
        assert_eq!(
            format!(
                "http://k2jvslbl2n1p4suo7yr973y3v7pfautpxba2jeb9fpmjil0l3lppcgi3.ipns.localhost:{}/",
                test_setup.gateway_addr.port()
            ),
            res.headers().get("Location").unwrap().to_str().unwrap()
        );

        // IPNS + DNSLink
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            "/ipns/en.wikipedia-on-ipfs.org",
            None,
        )
        .await;

        assert_eq!(http::StatusCode::MOVED_PERMANENTLY, res.status());
        assert_eq!(
            format!(
                "http://en-wikipedia--on--ipfs-org.ipns.localhost:{}/",
                test_setup.gateway_addr.port()
            ),
            res.headers().get("Location").unwrap().to_str().unwrap()
        );

        // IPNS + DNSLink
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            "/ipns/12D3KooWJHxkQKX8C5KAyqEPhn2ssT2in4TExyG9SXxi519tycL9",
            None,
        )
        .await;

        assert_eq!(http::StatusCode::MOVED_PERMANENTLY, res.status());
        assert_eq!(
            format!(
                "http://k51qzi5uqu5djbl2zsl8ooauuh7wb1ycesq93g72iym71shji1pbntl1vuyuk2.ipns.localhost:{}/",
                test_setup.gateway_addr.port()
            ),
            res.headers().get("Location").unwrap().to_str().unwrap()
        );

        // X-Forwarded-Proto
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            &format!("/ipfs/{}/{}", test_setup.root_cid, "world.txt"),
            Some(&[("x-forwarded-proto", "https")]),
        )
        .await;

        assert_eq!(http::StatusCode::MOVED_PERMANENTLY, res.status());
        assert_eq!(
            format!(
                "https://{}.ipfs.localhost:{}/world.txt",
                test_setup.root_cid,
                test_setup.gateway_addr.port()
            ),
            res.headers().get("Location").unwrap().to_str().unwrap(),
        );

        // X-Forwarded-Host
        let res = do_request(
            "GET",
            &format!("localhost:{}", test_setup.gateway_addr.port()),
            &format!("/ipfs/{}/{}", test_setup.root_cid, "world.txt"),
            Some(&[("x-forwarded-host", "ipfs.io")]),
        )
        .await;

        assert_eq!(http::StatusCode::MOVED_PERMANENTLY, res.status());
        assert_eq!(
            format!("http://{}.ipfs.ipfs.io/world.txt", test_setup.root_cid,),
            res.headers().get("Location").unwrap().to_str().unwrap(),
        );

        test_setup.shutdown().await
    }
}
