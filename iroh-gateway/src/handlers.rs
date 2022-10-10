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
use futures::TryStreamExt;
use handlebars::Handlebars;
use iroh_metrics::{core::MRecorder, gateway::GatewayMetrics, get_current_trace_id, inc};
use iroh_resolver::{
    resolver::{CidOrDomain, ContentLoader, OutMetrics, UnixfsType},
    unixfs::Link,
};
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
use tower_http::{compression::CompressionLayer, trace::TraceLayer};
use tracing::info_span;
use url::Url;
use urlencoding::encode;

use crate::{
    client::{FileResult, Request},
    constants::*,
    core::State,
    error::GatewayError,
    headers::*,
    response::{get_response_format, GatewayResponse, ResponseFormat},
};

/// Trait describing what needs to be accessed on the configuration
/// from the shared state.
pub trait StateConfig: std::fmt::Debug + Sync + Send {
    fn rpc_client(&self) -> &iroh_rpc_client::Config;

    fn port(&self) -> u16;

    fn user_headers(&self) -> &HeaderMap<HeaderValue>;
}

pub fn get_app_routes<T: ContentLoader + std::marker::Unpin>(state: &Arc<State<T>>) -> Router {
    // todo(arqu): ?uri=... https://github.com/ipfs/go-ipfs/pull/7802
    Router::new()
        .route("/:scheme/:cid", get(get_handler::<T>))
        .route("/:scheme/:cid/*cpath", get(get_handler::<T>))
        .route("/health", get(health_check))
        .layer(Extension(Arc::clone(state)))
        .layer(
            ServiceBuilder::new()
                // Handle errors from middleware
                .layer(Extension(Arc::clone(state)))
                .layer(CompressionLayer::new())
                .layer(HandleErrorLayer::new(middleware_error_handler::<T>))
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
        )
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

#[tracing::instrument(skip(state))]
pub async fn get_handler<T: ContentLoader + std::marker::Unpin>(
    Extension(state): Extension<Arc<State<T>>>,
    Path(params): Path<HashMap<String, String>>,
    Query(query_params): Query<GetParams>,
    request_headers: HeaderMap,
) -> Result<GatewayResponse, GatewayError> {
    inc!(GatewayMetrics::Requests);
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

    if check_bad_bits(&state, cid, cpath).await {
        return Err(error(
            StatusCode::FORBIDDEN,
            "CID is in the denylist",
            &state,
        ));
    }

    let full_content_path = format!("/{}/{}{}", scheme, cid, cpath);
    let resolved_path: iroh_resolver::resolver::Path = full_content_path
        .parse()
        .map_err(|e: anyhow::Error| e.to_string())
        .map_err(|e| error(StatusCode::BAD_REQUEST, &e, &state))?;
    let resolved_cid = resolved_path.root();

    if check_bad_bits(&state, resolved_cid.to_string().as_str(), cpath).await {
        return Err(error(
            StatusCode::FORBIDDEN,
            "CID is in the denylist",
            &state,
        ));
    }

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
    add_user_headers(&mut headers, state.config.user_headers().clone());
    let hv = match HeaderValue::from_str(&full_content_path) {
        Ok(hv) => hv,
        Err(err) => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                &format!("invalid header: {}", err),
                &state,
            ));
        }
    };
    headers.insert(&HEADER_X_IPFS_PATH, hv);

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
pub async fn health_check() -> String {
    "OK".to_string()
}

#[tracing::instrument()]
fn protocol_handler_redirect<T: ContentLoader>(
    uri_param: String,
    state: &State<T>,
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
fn service_worker_check<T: ContentLoader>(
    request_headers: &HeaderMap,
    cpath: String,
    state: &State<T>,
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
fn unsuported_header_check<T: ContentLoader>(
    request_headers: &HeaderMap,
    state: &State<T>,
) -> Result<(), GatewayError> {
    if request_headers.contains_key(&HEADER_X_IPFS_GATEWAY_PREFIX) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "Unsupported HTTP header",
            state,
        ));
    }
    Ok(())
}

pub async fn check_bad_bits<T: ContentLoader>(state: &State<T>, cid: &str, path: &str) -> bool {
    // check if cid is in the denylist
    if state.bad_bits.is_some() {
        let bad_bits = state.bad_bits.as_ref();
        if let Some(bbits) = bad_bits {
            if bbits.read().await.is_bad(cid, path) {
                return true;
            }
        }
    }
    false
}

#[tracing::instrument()]
fn etag_check<T: ContentLoader>(
    request_headers: &HeaderMap,
    resolved_cid: &CidOrDomain,
    format: &ResponseFormat,
    state: &State<T>,
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
async fn serve_raw<T: ContentLoader + std::marker::Unpin>(
    req: &Request,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let (body, metadata) = state
        .client
        .get_file(req.resolved_path.clone(), start_time)
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e, &state))?;

    match body {
        FileResult::File(body) => {
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
        FileResult::Directory(_) => Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot serve directory as raw",
            &state,
        )),
    }
}

#[tracing::instrument()]
async fn serve_car<T: ContentLoader + std::marker::Unpin>(
    req: &Request,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let (body, metadata) = state
        .client
        .get_file(req.resolved_path.clone(), start_time)
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e, &state))?;

    match body {
        FileResult::File(body) => {
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
        FileResult::Directory(_) => Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot serve directory as car file",
            &state,
        )),
    }
}

#[tracing::instrument()]
async fn serve_car_recursive<T: ContentLoader + std::marker::Unpin>(
    req: &Request,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    let body = state
        .client
        .clone()
        .get_car_recursive(req.resolved_path.clone(), start_time)
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
async fn serve_fs<T: ContentLoader + std::marker::Unpin>(
    req: &Request,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let (body, metadata) = state
        .client
        .get_file(req.resolved_path.clone(), start_time)
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e, &state))?;

    add_ipfs_roots_headers(&mut headers, metadata.clone());
    match body {
        FileResult::Directory(res) => {
            let dir_list: anyhow::Result<Vec<_>> = res
                .unixfs_read_dir(&state.client.resolver, OutMetrics { start: start_time })
                .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string(), &state))?
                .expect("already known this is a directory")
                .try_collect()
                .await;
            match dir_list {
                Ok(dir_list) => serve_fs_dir(&dir_list, req, state, headers, start_time).await,
                Err(e) => {
                    tracing::warn!("failed to read dir: {:?}", e);
                    Err(error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to read dir listing",
                        &state,
                    ))
                }
            }
        }
        FileResult::File(body) => {
            match metadata.unixfs_type {
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
                    response(StatusCode::OK, body, headers)
                }
                None => Err(error(
                    StatusCode::BAD_REQUEST,
                    "couldn't determine unixfs type",
                    &state,
                )),
            }
        }
    }
}

#[tracing::instrument()]
async fn serve_fs_dir<T: ContentLoader + std::marker::Unpin>(
    dir_list: &[Link],
    req: &Request,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    let force_dir = req.query_params.force_dir.unwrap_or(false);
    let has_index = dir_list.iter().any(|l| {
        l.name
            .as_ref()
            .map(|l| l.starts_with("index.html"))
            .unwrap_or_default()
    });
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
        .iter()
        .map(|l| {
            let name = l.name.as_deref().unwrap_or_default();
            let mut link = Map::new();
            link.insert("name".to_string(), Json::String(get_filename(name)));
            link.insert(
                "path".to_string(),
                Json::String(format!("{}{}", root_path, name)),
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
fn error<T: ContentLoader>(
    status_code: StatusCode,
    message: &str,
    state: &State<T>,
) -> GatewayError {
    inc!(GatewayMetrics::ErrorCount);
    GatewayError {
        status_code,
        message: message.to_string(),
        trace_id: get_current_trace_id().to_string(),
    }
}

#[tracing::instrument()]
pub async fn middleware_error_handler<T: ContentLoader>(
    Extension(state): Extension<Arc<State<T>>>,
    err: BoxError,
) -> impl IntoResponse {
    inc!(GatewayMetrics::FailCount);
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
