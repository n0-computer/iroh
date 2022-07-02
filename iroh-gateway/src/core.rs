use async_recursion::async_recursion;
use axum::{
    body::{self, Body, HttpBody},
    error_handling::HandleErrorLayer,
    extract::{Extension, Path, Query},
    http::{header::*, StatusCode},
    response::IntoResponse,
    routing::get,
    BoxError, Router,
};
use bytes::Bytes;
use handlebars::Handlebars;
use iroh_metrics::{gateway::Metrics, get_current_trace_id};
use iroh_resolver::resolver::{CidOrDomain, UnixfsType};
use iroh_rpc_client::Client as RpcClient;
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use serde_json::{
    json,
    value::{Map, Value as Json},
};
use serde_qs;
use std::{
    collections::HashMap,
    error::Error,
    fmt::Write,
    sync::Arc,
    time::{self, Duration},
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info_span;
use url::Url;
use urlencoding::encode;

use crate::{
    client::{Client, Request},
    config::Config,
    constants::*,
    error::GatewayError,
    headers::*,
    response::{get_response_format, GatewayResponse, ResponseFormat},
    rpc, templates,
};

#[derive(Debug)]
pub struct Core {
    state: Arc<State>,
}

#[derive(Debug)]
pub struct State {
    config: Config,
    client: Client,
    rpc_client: iroh_rpc_client::Client,
    handlebars: HashMap<String, String>,
    pub metrics: Metrics,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GetParams {
    // todo(arqu): swap this for ResponseFormat
    /// specifies the expected format of the response
    format: Option<String>,
    /// specifies the desired filename of the response
    filename: Option<String>,
    /// specifies whether the response should be of disposition inline or attachment
    download: Option<bool>,
    /// specifies whether the response should render a directory even if index.html is present
    force_dir: Option<bool>,
    /// uri query parameter for handling navigator.registerProtocolHandler Web API requests
    uri: Option<String>,
    recursive: Option<bool>,
}

impl GetParams {
    pub fn to_query_string(&self) -> String {
        let q = serde_qs::to_string(self).unwrap();
        if q.is_empty() {
            q
        } else {
            format!("?{}", q)
        }
    }
}

impl Core {
    pub async fn new(
        config: Config,
        metrics: Metrics,
        registry: &mut Registry,
    ) -> anyhow::Result<Self> {
        tokio::spawn(async move {
            // TODO: handle error
            rpc::new(config.rpc_addr).await
        });
        let rpc_client = RpcClient::new(&config.rpc_client).await?;
        let mut templates = HashMap::new();
        templates.insert("dir_list".to_string(), templates::DIR_LIST.to_string());
        templates.insert("not_found".to_string(), templates::NOT_FOUND.to_string());
        let client = Client::new(&rpc_client, registry);

        Ok(Self {
            state: Arc::new(State {
                config,
                client,
                rpc_client,
                metrics,
                handlebars: templates,
            }),
        })
    }

    pub fn server(
        self,
    ) -> axum::Server<hyper::server::conn::AddrIncoming, axum::routing::IntoMakeService<Router>>
    {
        // todo(arqu): ?uri=... https://github.com/ipfs/go-ipfs/pull/7802
        let app = Router::new()
            .route("/:scheme/:cid", get(get_handler))
            .route("/:scheme/:cid/*cpath", get(get_handler))
            .route("/health", get(health_check))
            .layer(Extension(Arc::clone(&self.state)))
            .layer(
                ServiceBuilder::new()
                    // Handle errors from middleware
                    .layer(Extension(Arc::clone(&self.state)))
                    .layer(HandleErrorLayer::new(middleware_error_handler))
                    .load_shed()
                    .concurrency_limit(2048)
                    .timeout(Duration::from_secs(60))
                    .into_inner(),
            )
            .layer(
                // Tracing span for each request
                TraceLayer::new_for_http().make_span_with(|request: &http::Request<Body>| {
                    info_span!(
                        "request",
                        method = %request.method(),
                        uri = %request.uri(),
                    )
                }),
            );
        // todo(arqu): make configurable
        let addr = format!("0.0.0.0:{}", self.state.config.port);

        axum::Server::bind(&addr.parse().unwrap())
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve(app.into_make_service())
    }
}

#[tracing::instrument(skip(state))]
async fn get_handler(
    Extension(state): Extension<Arc<State>>,
    Path(params): Path<HashMap<String, String>>,
    Query(query_params): Query<GetParams>,
    request_headers: HeaderMap,
) -> Result<GatewayResponse, GatewayError> {
    state.metrics.requests_total.inc();
    let start_time = time::Instant::now();
    // parse path params
    let scheme = params.get("scheme").unwrap();
    if scheme != SCHEME_IPFS && scheme != SCHEME_IPNS {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid scheme, must be ipfs or ipns",
            &state,
        ));
    }
    let cid = params.get("cid").unwrap();
    let cpath = "".to_string();
    let cpath = params.get("cpath").unwrap_or(&cpath);
    let query_params_copy = query_params.clone();

    let uri_param = query_params.uri.clone().unwrap_or_default();
    if !uri_param.is_empty() {
        return protocol_handler_redirect(uri_param, &state);
    }
    service_worker_check(&request_headers, cpath.to_string(), &state)?;
    unsuported_header_check(&request_headers, &state)?;

    let full_content_path = format!("/{}/{}{}", scheme, cid, cpath);
    let resolved_path: iroh_resolver::resolver::Path = full_content_path
        .parse()
        .map_err(|e: anyhow::Error| e.to_string())
        .map_err(|e| error(StatusCode::BAD_REQUEST, &e, &state))?;
    let resolved_cid = resolved_path.root();

    // parse query params
    let format = match get_response_format(&request_headers, query_params.format) {
        Ok(format) => format,
        Err(err) => {
            return Err(error(StatusCode::BAD_REQUEST, &err, &state));
        }
    };

    let query_file_name = query_params.filename.unwrap_or_default();
    let download = query_params.download.unwrap_or_default();
    let recursive = query_params.recursive.unwrap_or_default();

    let mut headers = HeaderMap::new();

    if let Some(resp) = etag_check(&request_headers, resolved_cid, &format, &state) {
        return Ok(resp);
    }

    // init headers
    format.write_headers(&mut headers);
    add_user_headers(&mut headers, state.config.headers.clone());
    headers.insert(
        &HEADER_X_IPFS_PATH,
        HeaderValue::from_str(&full_content_path).unwrap(),
    );

    // handle request and fetch data
    let req = Request {
        format,
        cid: resolved_path.root().clone(),
        resolved_path,
        query_file_name,
        content_path: full_content_path.to_string(),
        download,
        query_params: query_params_copy,
    };

    if recursive {
        serve_car_recursive(&req, state, headers, start_time).await
    } else {
        match req.format {
            ResponseFormat::Raw => serve_raw(&req, state, headers, start_time).await,
            ResponseFormat::Car => serve_car(&req, state, headers, start_time).await,
            ResponseFormat::Fs(_) => serve_fs(&req, state, headers, start_time).await,
        }
    }
}

#[tracing::instrument()]
async fn health_check() -> String {
    "OK".to_string()
}

#[tracing::instrument()]
fn protocol_handler_redirect(
    uri_param: String,
    state: &State,
) -> Result<GatewayResponse, GatewayError> {
    let u = match Url::parse(&uri_param) {
        Ok(u) => u,
        Err(e) => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                &format!("invalid uri: {}", e),
                state,
            ));
        }
    };
    let uri_scheme = u.scheme();
    if uri_scheme != SCHEME_IPFS && uri_scheme != SCHEME_IPNS {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid uri scheme, must be ipfs or ipns",
            state,
        ));
    }
    let mut uri_path = u.path().to_string();
    let uri_query = u.query();
    if uri_query.is_some() {
        let encoded_query = encode(uri_query.unwrap());
        write!(uri_path, "?{}", encoded_query)
            .map_err(|e| error(StatusCode::BAD_REQUEST, &e.to_string(), state))?;
    }
    let uri_host = u.host().unwrap().to_string();
    let redirect_uri = format!("{}://{}{}", uri_scheme, uri_host, uri_path);
    Ok(GatewayResponse::redirect_permanently(&redirect_uri))
}

#[tracing::instrument()]
fn service_worker_check(
    request_headers: &HeaderMap,
    cpath: String,
    state: &State,
) -> Result<(), GatewayError> {
    if request_headers.contains_key(&HEADER_SERVICE_WORKER) {
        let sw = request_headers.get(&HEADER_SERVICE_WORKER).unwrap();
        if sw.to_str().unwrap() == "script" && cpath.is_empty() {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "Service Worker not supported",
                state,
            ));
        }
    }
    Ok(())
}

#[tracing::instrument()]
fn unsuported_header_check(request_headers: &HeaderMap, state: &State) -> Result<(), GatewayError> {
    if request_headers.contains_key(&HEADER_X_IPFS_GATEWAY_PREFIX) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Unsupported HTTP header",
            state,
        ));
    }
    Ok(())
}

#[tracing::instrument()]
fn etag_check(
    request_headers: &HeaderMap,
    resolved_cid: &CidOrDomain,
    format: &ResponseFormat,
    state: &State,
) -> Option<GatewayResponse> {
    if request_headers.contains_key("If-None-Match") {
        // todo(arqu): handle dir etags
        let cid_etag = get_etag(resolved_cid, Some(format.clone()));
        let inm = request_headers
            .get("If-None-Match")
            .unwrap()
            .to_str()
            .unwrap();
        if etag_matches(inm, &cid_etag) {
            return Some(GatewayResponse::not_modified());
        }
    }
    None
}

#[tracing::instrument()]
async fn serve_raw(
    req: &Request,
    state: Arc<State>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let (body, metadata) = state
        .client
        .get_file(
            req.resolved_path.clone(),
            &state.rpc_client,
            start_time,
            &state.metrics,
        )
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e, &state))?;

    set_content_disposition_headers(
        &mut headers,
        format!("{}.bin", req.cid).as_str(),
        DISPOSITION_ATTACHMENT,
    );
    set_etag_headers(&mut headers, get_etag(&req.cid, Some(req.format.clone())));
    add_cache_control_headers(&mut headers, metadata.clone());
    add_ipfs_roots_headers(&mut headers, metadata);
    response(StatusCode::OK, body, headers)
}

#[tracing::instrument()]
async fn serve_car(
    req: &Request,
    state: Arc<State>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let (body, metadata) = state
        .client
        .get_file(
            req.resolved_path.clone(),
            &state.rpc_client,
            start_time,
            &state.metrics,
        )
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e, &state))?;

    set_content_disposition_headers(
        &mut headers,
        format!("{}.car", req.cid).as_str(),
        DISPOSITION_ATTACHMENT,
    );

    // todo(arqu): this should be root cid
    let etag = format!("W/{}", get_etag(&req.cid, Some(req.format.clone())));
    set_etag_headers(&mut headers, etag);
    // todo(arqu): check if etag matches for root cid
    add_ipfs_roots_headers(&mut headers, metadata);
    response(StatusCode::OK, body, headers)
}

#[tracing::instrument()]
async fn serve_car_recursive(
    req: &Request,
    state: Arc<State>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: actually package as car file

    let body = state
        .client
        .clone()
        .get_file_recursive(
            req.resolved_path.clone(),
            state.rpc_client.clone(),
            start_time,
            state.metrics.clone(),
        )
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e, &state))?;

    set_content_disposition_headers(
        &mut headers,
        format!("{}.car", req.cid).as_str(),
        DISPOSITION_ATTACHMENT,
    );

    // todo(arqu): this should be root cid
    let etag = format!("W/{}", get_etag(&req.cid, Some(req.format.clone())));
    set_etag_headers(&mut headers, etag);
    // todo(arqu): check if etag matches for root cid
    // add_ipfs_roots_headers(&mut headers, metadata);
    response(StatusCode::OK, body, headers)
}

#[tracing::instrument()]
#[async_recursion]
async fn serve_fs(
    req: &Request,
    state: Arc<State>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let (mut body, metadata) = state
        .client
        .get_file(
            req.resolved_path.clone(),
            &state.rpc_client,
            start_time,
            &state.metrics,
        )
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e, &state))?;

    add_ipfs_roots_headers(&mut headers, metadata.clone());
    match metadata.unixfs_type {
        Some(UnixfsType::Dir) => {
            if let Some(dir_list_data) = body.data().await {
                let dir_list = match dir_list_data {
                    Ok(b) => b,
                    Err(_) => {
                        return Err(error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "failed to read dir listing",
                            &state,
                        ));
                    }
                };
                return serve_fs_dir(&dir_list, req, state, headers, start_time).await;
            } else {
                return Err(error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to read dir listing",
                    &state,
                ));
            }
        }
        Some(_) => {
            // todo(arqu): error on no size
            // todo(arqu): add lazy seeking
            add_cache_control_headers(&mut headers, metadata.clone());
            set_etag_headers(&mut headers, get_etag(&req.cid, Some(req.format.clone())));
            let name = add_content_disposition_headers(
                &mut headers,
                &req.query_file_name,
                &req.content_path,
                req.download,
            );
            if metadata.unixfs_type == Some(UnixfsType::Symlink) {
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_str("inode/symlink").unwrap(),
                );
            } else {
                add_content_type_headers(&mut headers, &name);
            }
        }
        None => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "couldn't determine unixfs type",
                &state,
            ));
        }
    }
    response(StatusCode::OK, body, headers)
}

#[tracing::instrument()]
async fn serve_fs_dir(
    dir_list: &Bytes,
    req: &Request,
    state: Arc<State>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    let dir_list = std::str::from_utf8(&dir_list[..]).unwrap();
    let force_dir = req.query_params.force_dir.unwrap_or(false);
    let has_index = dir_list.lines().any(|l| l.starts_with("index.html"));
    if !force_dir && has_index {
        if !req.content_path.ends_with('/') {
            let redirect_path = format!(
                "{}/{}",
                req.content_path,
                req.query_params.to_query_string()
            );
            return Ok(GatewayResponse::redirect(&redirect_path));
        }
        let mut new_req = req.clone();
        new_req.resolved_path.push("index.html");
        new_req.content_path = format!("{}/index.html", req.content_path);
        return serve_fs(&new_req, state, headers, start_time).await;
    }

    headers.insert(CONTENT_TYPE, HeaderValue::from_str("text/html").unwrap());
    // todo(arqu): set etag
    // set_etag_headers(&mut headers, metadata.dir_hash.clone());

    let mut template_data: Map<String, Json> = Map::new();
    let mut root_path = req.content_path.clone();
    if !root_path.ends_with('/') {
        root_path.push('/');
    }
    let links = dir_list
        .lines()
        .map(|line| {
            let mut link = Map::new();
            link.insert("name".to_string(), Json::String(get_filename(line)));
            link.insert(
                "path".to_string(),
                Json::String(format!("{}{}", root_path, line)),
            );
            link
        })
        .collect::<Vec<Map<String, Json>>>();
    template_data.insert("links".to_string(), json!(links));
    let reg = Handlebars::new();
    let dir_template = state.handlebars.get("dir_list").unwrap();
    let res = reg.render_template(dir_template, &template_data).unwrap();
    response(StatusCode::OK, Body::from(res), headers)
}

#[tracing::instrument(skip(body))]
fn response<B>(
    status_code: StatusCode,
    body: B,
    headers: HeaderMap,
) -> Result<GatewayResponse, GatewayError>
where
    B: 'static + HttpBody<Data = Bytes> + Send,
    <B as HttpBody>::Error: Into<Box<dyn Error + Send + Sync + 'static>>,
{
    Ok(GatewayResponse {
        status_code,
        body: body::boxed(body),
        headers,
        trace_id: get_current_trace_id().to_string(),
    })
}

#[tracing::instrument()]
fn error(status_code: StatusCode, message: &str, state: &State) -> GatewayError {
    state.metrics.error_count.inc();
    GatewayError {
        status_code,
        message: message.to_string(),
        trace_id: get_current_trace_id().to_string(),
    }
}

#[tracing::instrument()]
async fn middleware_error_handler(
    Extension(state): Extension<Arc<State>>,
    err: BoxError,
) -> impl IntoResponse {
    state.metrics.fail_count.inc();
    if err.is::<tower::timeout::error::Elapsed>() {
        return error(StatusCode::REQUEST_TIMEOUT, "request timed out", &state);
    }

    if err.is::<tower::load_shed::error::Overloaded>() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "service is overloaded, try again later",
            &state,
        );
    }

    return error(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("unhandled internal error: {}", err).as_str(),
        &state,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_rpc_client::Config as RpcClientConfig;
    use prometheus_client::registry::Registry;

    #[tokio::test]
    async fn gateway_health() {
        let mut config = Config::new(
            false,
            false,
            false,
            0,
            "0.0.0.0:0".parse().unwrap(),
            RpcClientConfig {
                gateway_addr: "0.0.0.0:0".parse().unwrap(),
                p2p_addr: "0.0.0.0:0".parse().unwrap(),
                store_addr: "0.0.0.0:0".parse().unwrap(),
            },
        );
        config.set_default_headers();

        let mut prom_registry = Registry::default();
        let gw_metrics = Metrics::new(&mut prom_registry);
        let handler = Core::new(config, gw_metrics, &mut prom_registry)
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

        assert_eq!(StatusCode::OK, res.status());
        let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
        assert_eq!(b"OK", &body[..]);
        core_task.abort();
        core_task.await.unwrap_err();
    }
}
