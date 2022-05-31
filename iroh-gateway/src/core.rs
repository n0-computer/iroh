use async_recursion::async_recursion;
use axum::{
    body::{self, Body, BoxBody, HttpBody},
    error_handling::HandleErrorLayer,
    extract::{Extension, Path, Query},
    http::{header::*, StatusCode},
    response::IntoResponse,
    routing::get,
    BoxError, Router,
};
use bytes::Bytes;
use handlebars::Handlebars;
use iroh_resolver::resolver::UnixfsType;
use iroh_rpc_client::Client as RpcClient;
use serde::{Deserialize, Serialize};
use serde_json::{
    json,
    value::{Map, Value as Json},
};
use serde_qs;
use urlencoding::encode;
use std::{
    collections::HashMap,
    error::Error,
    sync::Arc,
    time::{self, Duration},
    fmt::Write,
};
use url::Url;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{info, info_span};

use crate::{
    client::{Client, Request},
    config::Config,
    constants::*,
    error::GatewayError,
    headers::*,
    metrics::{get_current_trace_id, Metrics},
    response::{get_response_format, GatewayResponse, ResponseFormat},
    rpc,
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
    pub async fn new(config: Config, metrics: Metrics) -> anyhow::Result<Self> {
        rpc::new(config.rpc.client_config.gateway_addr).await?;
        let rpc_client = RpcClient::new(&config.rpc.client_config).await?;
        let mut templates = HashMap::new();
        let dir_template = fs::read_to_string("templates/dir_list.hbs").await?;
        templates.insert("dir_list".to_string(), dir_template);

        Ok(Self {
            state: Arc::new(State {
                config,
                client: Client::new(&rpc_client),
                rpc_client,
                metrics,
                handlebars: templates,
            }),
        })
    }

    pub async fn serve(self) {
        // todo(arqu): ?uri=... https://github.com/ipfs/go-ipfs/pull/7802
        let app = Router::new()
            .route("/:scheme/:cid", get(get_handler))
            .route("/:scheme/:cid/*cpath", get(get_handler))
            .layer(Extension(Arc::clone(&self.state)))
            .layer(
                ServiceBuilder::new()
                    // Handle errors from middleware
                    .layer(Extension(Arc::clone(&self.state)))
                    .layer(HandleErrorLayer::new(middleware_error_handler))
                    .load_shed()
                    .concurrency_limit(1024)
                    .timeout(Duration::from_secs(120))
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

        info!("listening on {}", addr);
        axum::Server::bind(&addr.parse().unwrap())
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }
}

#[tracing::instrument()]
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
    if scheme != "ipfs" && scheme != "ipns" {
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
        let u = Url::parse(&uri_param);
        if u.is_err() {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "invalid uri parameter",
                &state,
            ));
        }
        let u = u.unwrap();
        let uri_scheme = u.scheme().to_string();
        if uri_scheme != "ipfs" && uri_scheme != "ipns" {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "invalid uri scheme, must be ipfs or ipns",
                &state,
            ));
        }
        let mut uri_path = u.path().to_string();
        let uri_query = u.query();
        if uri_query.is_some() {
            let encoded_query = encode(uri_query.unwrap());
            write!(
                uri_path,
                "?{}",
                encoded_query
            ).map_err(|e| error(StatusCode::BAD_REQUEST, &e.to_string(), &state))?;
        }
        let uri_host = u.host().unwrap().to_string();
        let redirect_uri = format!("{}://{}{}", uri_scheme, uri_host, uri_path);
        return Ok(GatewayResponse::redirect_permanently(&redirect_uri));
    }

    if request_headers.contains_key(&HEADER_SERVICE_WORKER) {
        let sw = request_headers.get(&HEADER_SERVICE_WORKER).unwrap();
        if sw.to_str().unwrap() == "script" && cpath.is_empty() {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "Service Worker not supported",
                &state,
            ));
        }
    }
    if request_headers.contains_key(&HEADER_X_IPFS_GATEWAY_PREFIX) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Unsupported HTTP header",
            &state,
        ));
    }

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

    let mut headers = HeaderMap::new();

    if request_headers.contains_key("If-None-Match") {
        // todo(arqu): handle dir etags
        let cid_etag = get_etag(resolved_cid, Some(format.clone()));
        let inm = request_headers
            .get("If-None-Match")
            .unwrap()
            .to_str()
            .unwrap();
        if etag_matches(inm, &cid_etag) {
            return response(StatusCode::NOT_MODIFIED, BoxBody::default(), headers);
        }
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

    match req.format {
        ResponseFormat::Raw => serve_raw(&req, state, headers, start_time).await,
        ResponseFormat::Car => serve_car(&req, state, headers, start_time).await,
        ResponseFormat::Fs(_) => serve_fs(&req, state, headers, start_time).await,
    }
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
            Arc::clone(&state),
        )
        .await
        .unwrap();
    // .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

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
            Arc::clone(&state),
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
            Arc::clone(&state),
        )
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e, &state))?;

    add_ipfs_roots_headers(&mut headers, metadata.clone());
    match metadata.unixfs_type {
        Some(UnixfsType::Dir) => {
            let dir_list = match body.data().await {
                Some(data) => match data {
                    Ok(b) => b,
                    Err(_) => {
                        return Err(error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "failed to read dir listing",
                            &state,
                        ));
                    }
                },
                None => {
                    return Err(error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to read dir listing",
                        &state,
                    ));
                }
            };
            let dir_list = String::from_utf8(dir_list.to_vec()).unwrap();
            let dir_list_lines = dir_list.lines();
            let force_dir = req.query_params.force_dir.unwrap_or(false);
            if !force_dir {
                for line in dir_list_lines.clone() {
                    if line == "index.html" {
                        if !req.content_path.ends_with('/') {
                            let redirect_path = format!(
                                "{}/{}",
                                req.content_path,
                                req.query_params.to_query_string()
                            );
                            return Ok(GatewayResponse::redirect(&redirect_path));
                        }
                        let mut new_req = req.clone();
                        new_req
                            .resolved_path
                            .extend_tail(vec!["index.html".to_string()]);
                        new_req.content_path = format!("{}/index.html", req.content_path);
                        return serve_fs(&new_req, state, headers, start_time).await;
                    }
                }
            }

            headers.insert(CONTENT_TYPE, HeaderValue::from_str("text/html").unwrap());
            // todo(arqu): set etag
            // set_etag_headers(&mut headers, metadata.dir_hash.clone());

            let mut template_data: Map<String, Json> = Map::new();
            let mut root_path = req.content_path.clone();
            if !root_path.ends_with('/') {
                root_path.push('/');
            }
            let links = dir_list_lines
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
            return response(StatusCode::OK, Body::from(res), headers);
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
