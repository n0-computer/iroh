use async_recursion::async_recursion;
use axum::extract::Host;
use axum::routing::any;
use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    extract::{Extension, Path as AxumPath, Query},
    http::{header::*, Request as HttpRequest, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{get, head},
    BoxError, Router,
};
use cid::Cid;
use futures::TryStreamExt;
use handlebars::Handlebars;
use http::Method;
use iroh_metrics::{core::MRecorder, gateway::GatewayMetrics, inc, resolver::OutMetrics};
use iroh_resolver::resolver::{CidOrDomain, UnixfsType};
use iroh_unixfs::{content_loader::ContentLoader, Link};
use iroh_util::human::format_bytes;
use serde_json::{
    json,
    value::{Map, Value as Json},
};
use std::{
    collections::HashMap,
    fmt::Write,
    ops::Range,
    sync::Arc,
    time::{self, Duration},
};

use iroh_resolver::Path;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{compression::CompressionLayer, trace::TraceLayer};
use tracing::info_span;
use url::Url;
use urlencoding::encode;

use crate::handler_params::{
    inlined_dns_link_to_dns_link, recode_path_to_inlined_dns_link, DefaultHandlerPathParams,
    GetParams, SubdomainHandlerPathParams,
};
use crate::ipfs_request::IpfsRequest;
use crate::text::IpfsSubdomain;
use crate::{
    client::FileResult,
    constants::*,
    core::State,
    error::GatewayError,
    headers::*,
    response::{get_response_format, GatewayResponse, ResponseFormat},
    templates::{icon_class_name, ICONS_STYLESHEET, STYLESHEET},
};

enum RequestPreprocessingResult {
    RespondImmediately(GatewayResponse),
    ShouldRequestData(Box<IpfsRequest>),
}

/// Trait describing what needs to be accessed on the configuration
/// from the shared state.
pub trait StateConfig: std::fmt::Debug + Sync + Send {
    fn rpc_client(&self) -> &iroh_rpc_client::Config;
    fn public_url_base(&self) -> &str;
    fn port(&self) -> u16;
    fn user_headers(&self) -> &HeaderMap<HeaderValue>;
    fn redirect_to_subdomain(&self) -> bool;
}

pub fn get_app_routes<T: ContentLoader + Unpin>(state: &Arc<State<T>>) -> Router {
    let cors = crate::cors::cors_from_headers(state.config.user_headers());

    // todo(arqu): ?uri=... https://github.com/ipfs/go-ipfs/pull/7802
    let path_router = Router::new()
        .route("/:scheme/:cid_or_domain", get(path_handler::<T>))
        .route(
            "/:scheme/:cid_or_domain/*content_path",
            get(path_handler::<T>),
        )
        .route("/:scheme/:cid_or_domain/", get(path_handler::<T>))
        .route(
            "/:scheme/:cid_or_domain/*content_path",
            head(path_handler::<T>),
        )
        .route("/:scheme/:cid_or_domain/", head(path_handler::<T>))
        .route("/health", get(health_check))
        .route("/icons.css", get(stylesheet_icons))
        .route("/style.css", get(stylesheet_main))
        .route("/info", get(info));

    let subdomain_router = Router::new()
        .route("/*content_path", get(subdomain_handler::<T>))
        .route("/", get(subdomain_handler::<T>))
        .route("/*content_path", head(subdomain_handler::<T>))
        .route("/", head(subdomain_handler::<T>));

    let subdomain_router2 = subdomain_router.clone();
    let path_router2 = path_router.clone();

    Router::new()
        .route(
            "/*path",
            any(
                |Host(hostname): Host, request: hyper::Request<Body>| async move {
                    match IpfsSubdomain::try_from_str(&hostname) {
                        Some(_) => subdomain_router.oneshot(request).await,
                        None => path_router.oneshot(request).await,
                    }
                },
            ),
        )
        .route(
            "/",
            any(
                |Host(hostname): Host, request: hyper::Request<Body>| async move {
                    match IpfsSubdomain::try_from_str(&hostname) {
                        Some(_) => subdomain_router2.oneshot(request).await,
                        None => path_router2.oneshot(request).await,
                    }
                },
            ),
        )
        .layer(cors)
        .layer(Extension(Arc::clone(state)))
        .layer(
            ServiceBuilder::new()
                // Handle errors from middleware
                .layer(Extension(Arc::clone(state)))
                .layer(middleware::from_fn(request_middleware))
                .layer(CompressionLayer::new())
                .layer(HandleErrorLayer::new(middleware_error_handler))
                .load_shed()
                .concurrency_limit(2048 * 1024)
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
        )
}

async fn request_preprocessing<T: ContentLoader + Unpin>(
    state: &Arc<State<T>>,
    path: &Path,
    query_params: &GetParams,
    request_headers: &HeaderMap,
    response_headers: &mut HeaderMap,
    subdomain_mode: bool,
) -> Result<RequestPreprocessingResult, GatewayError> {
    if path.typ().as_str() != SCHEME_IPFS && path.typ().as_str() != SCHEME_IPNS {
        return Err(GatewayError::new(
            StatusCode::BAD_REQUEST,
            "invalid scheme, must be ipfs or ipns",
        ));
    }
    let content_path = path.to_relative_string();

    let uri_param = query_params.uri.clone().unwrap_or_default();
    if !uri_param.is_empty() {
        return protocol_handler_redirect(uri_param)
            .map(RequestPreprocessingResult::RespondImmediately);
    }
    service_worker_check(request_headers, &content_path)?;
    unsupported_header_check(request_headers)?;

    if let Some(cid) = path.cid() {
        if check_bad_bits(state, cid, &content_path).await {
            return Err(GatewayError::new(
                StatusCode::GONE,
                "CID is in the denylist",
            ));
        }
    }

    // parse query params
    let format = get_response_format(request_headers, &query_params.format)
        .map_err(|err| GatewayError::new(StatusCode::BAD_REQUEST, &err))?;
    let ipfs_request = state
        .client
        .build_ipfs_request(path, query_params, format.clone(), subdomain_mode)
        .await?;

    let resolved_cid = ipfs_request.path_metadata.metadata().resolved_path.last();
    let resolved_cid = match resolved_cid {
        Some(cid) => cid,
        None => {
            return Err(GatewayError::new(
                StatusCode::NOT_FOUND,
                "failed to resolve path",
            ))
        }
    };

    if check_bad_bits(state, resolved_cid, &content_path).await {
        return Err(GatewayError::new(
            StatusCode::GONE,
            "CID is in the denylist",
        ));
    }

    if handle_only_if_cached(request_headers, state, path.root()).await? {
        return Ok(RequestPreprocessingResult::RespondImmediately(
            GatewayResponse::new(StatusCode::OK, Body::empty(), HeaderMap::new()),
        ));
    }

    if let Some(resp) = etag_check(request_headers, &CidOrDomain::Cid(*resolved_cid), &format) {
        return Ok(RequestPreprocessingResult::RespondImmediately(resp));
    }

    // init headers
    format.write_headers(response_headers);
    add_user_headers(response_headers, state.config.user_headers().clone());
    let hv = match HeaderValue::from_str(&path.to_string()) {
        Ok(hv) => hv,
        Err(err) => {
            return Err(GatewayError::new(
                StatusCode::BAD_REQUEST,
                &format!("invalid header value: {err}"),
            ));
        }
    };
    response_headers.insert(&HEADER_X_IPFS_PATH, hv);

    Ok(RequestPreprocessingResult::ShouldRequestData(Box::new(
        ipfs_request,
    )))
}

pub async fn handler<T: ContentLoader + Unpin>(
    state: Arc<State<T>>,
    method: Method,
    path: &Path,
    query_params: &GetParams,
    request_headers: &HeaderMap,
    http_req: HttpRequest<Body>,
    subdomain_mode: bool,
) -> Result<GatewayResponse, GatewayError> {
    let start_time = time::Instant::now();
    let mut response_headers = HeaderMap::new();
    match request_preprocessing(
        &state,
        path,
        query_params,
        request_headers,
        &mut response_headers,
        subdomain_mode,
    )
    .await?
    {
        RequestPreprocessingResult::RespondImmediately(gateway_response) => Ok(gateway_response),
        RequestPreprocessingResult::ShouldRequestData(req) => match method {
            Method::HEAD => {
                add_content_length_header(&mut response_headers, req.path_metadata.metadata().size);
                Ok(GatewayResponse::empty(response_headers))
            }
            Method::GET => {
                if query_params.recursive.unwrap_or_default() {
                    serve_car_recursive(&req, state, response_headers, start_time).await
                } else {
                    match req.format {
                        ResponseFormat::Raw => {
                            serve_raw(&req, state, response_headers, &http_req, start_time).await
                        }
                        ResponseFormat::Car => {
                            serve_car(&req, state, response_headers, start_time).await
                        }
                        ResponseFormat::Fs(_) => {
                            serve_fs(&req, state, response_headers, &http_req, start_time).await
                        }
                    }
                }
            }
            _ => Err(GatewayError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
        },
    }
}

#[tracing::instrument(skip(state))]
pub async fn subdomain_handler<T: ContentLoader + Unpin>(
    Extension(state): Extension<Arc<State<T>>>,
    method: Method,
    Host(host): Host,
    AxumPath(path_params): AxumPath<SubdomainHandlerPathParams>,
    Query(query_params): Query<GetParams>,
    request_headers: HeaderMap,
    http_req: HttpRequest<Body>,
) -> Result<GatewayResponse, GatewayError> {
    inc!(GatewayMetrics::Requests);
    let parsed_subdomain_url = IpfsSubdomain::try_from_str(&host)
        .ok_or_else(|| GatewayError::new(StatusCode::BAD_REQUEST, "hostname is not compliant"))?;
    let path = Path::from_parts(
        parsed_subdomain_url.scheme,
        &inlined_dns_link_to_dns_link(parsed_subdomain_url.cid_or_domain),
        path_params.content_path.as_deref().unwrap_or("/"),
    )
    .map_err(|e| GatewayError::new(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let m = method.clone();
    let res = handler(
        state,
        method,
        &path,
        &query_params,
        &request_headers,
        http_req,
        true,
    )
    .await
    .map_err(|e| maybe_html_error(e, m, request_headers))?;
    Ok(res)
}

#[tracing::instrument(skip(state))]
pub async fn path_handler<T: ContentLoader + Unpin>(
    Extension(state): Extension<Arc<State<T>>>,
    method: Method,
    Host(host): Host,
    AxumPath(path_params): AxumPath<DefaultHandlerPathParams>,
    Query(query_params): Query<GetParams>,
    request_headers: HeaderMap,
    http_req: HttpRequest<Body>,
) -> Result<GatewayResponse, GatewayError> {
    inc!(GatewayMetrics::Requests);
    let path = Path::from_parts(
        &path_params.scheme,
        &path_params.cid_or_domain,
        path_params.content_path.as_deref().unwrap_or(""),
    )
    .map_err(|e| GatewayError::new(StatusCode::BAD_REQUEST, &e.to_string()))?;
    if state.config.redirect_to_subdomain() {
        Ok(redirect_path_handlers(&host, &path, &request_headers))
    } else {
        let m = method.clone();
        let res = handler(
            state,
            method,
            &path,
            &query_params,
            &request_headers,
            http_req,
            true,
        )
        .await
        .map_err(|e| maybe_html_error(e, m, request_headers))?;
        Ok(res)
    }
}

#[tracing::instrument()]
pub async fn health_check() -> String {
    "OK".to_string()
}

/// Some basic info about the service to respond from a `GET /info` request.
#[tracing::instrument]
pub async fn info() -> String {
    format!(
        "{bin} {version} ({git})\n\n{description}\n{license}\n{url}",
        bin = std::env!("CARGO_CRATE_NAME"),
        version = std::env!("CARGO_PKG_VERSION"),
        git = git_version::git_version!(
            prefix = "git:",
            cargo_prefix = "cargo:",
            fallback = "unknown"
        ),
        description = std::env!("CARGO_PKG_DESCRIPTION"),
        license = std::env!("CARGO_PKG_LICENSE"),
        url = env!("CARGO_PKG_REPOSITORY"),
    )
}

async fn stylesheet_main() -> (HeaderMap, &'static str) {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/css"),
    );
    (headers, STYLESHEET)
}

pub async fn stylesheet_icons() -> (HeaderMap, &'static str) {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/css"),
    );
    (headers, ICONS_STYLESHEET)
}

#[tracing::instrument()]
fn protocol_handler_redirect(uri_param: String) -> Result<GatewayResponse, GatewayError> {
    let u = match Url::parse(&uri_param) {
        Ok(u) => u,
        Err(e) => {
            return Err(GatewayError::new(
                StatusCode::BAD_REQUEST,
                &format!("invalid uri: {e}"),
            ));
        }
    };
    let uri_scheme = u.scheme();
    if uri_scheme != SCHEME_IPFS && uri_scheme != SCHEME_IPNS {
        return Err(GatewayError::new(
            StatusCode::BAD_REQUEST,
            "invalid uri scheme, must be ipfs or ipns",
        ));
    }
    let mut uri_path = u.path().to_string();
    let uri_query = u.query();
    if uri_query.is_some() {
        let encoded_query = encode(uri_query.unwrap());
        write!(uri_path, "?{encoded_query}")
            .map_err(|e| GatewayError::new(StatusCode::BAD_REQUEST, &e.to_string()))?;
    }
    let uri_host = u.host().unwrap().to_string();
    let redirect_uri = format!("{uri_scheme}://{uri_host}{uri_path}");
    Ok(GatewayResponse::redirect_permanently(&redirect_uri))
}

#[tracing::instrument()]
fn service_worker_check(
    request_headers: &HeaderMap,
    content_path: &str,
) -> Result<(), GatewayError> {
    if request_headers.contains_key(&HEADER_SERVICE_WORKER) {
        let sw = request_headers.get(&HEADER_SERVICE_WORKER).unwrap();
        if sw.to_str().unwrap() == "script" && content_path.is_empty() {
            return Err(GatewayError::new(
                StatusCode::BAD_REQUEST,
                "Service Worker not supported",
            ));
        }
    }
    Ok(())
}

#[tracing::instrument()]
fn unsupported_header_check(request_headers: &HeaderMap) -> Result<(), GatewayError> {
    if request_headers.contains_key(&HEADER_X_IPFS_GATEWAY_PREFIX) {
        return Err(GatewayError::new(
            StatusCode::BAD_REQUEST,
            "Unsupported HTTP header",
        ));
    }
    Ok(())
}

#[tracing::instrument()]
fn redirect_path_handlers(host: &str, path: &Path, request_headers: &HeaderMap) -> GatewayResponse {
    let target_host = request_headers
        .get(&HEADER_X_FORWARDED_HOST)
        .map(|hv| hv.to_str().unwrap())
        .unwrap_or(host);
    let target_proto = request_headers
        .get(&HEADER_X_FORWARDED_PROTO)
        .map(|hv| hv.to_str().unwrap())
        .unwrap_or("http");
    let content_path = path.to_relative_string();
    GatewayResponse::redirect_permanently(&format!(
        "{}://{}.{}.{}/{}",
        target_proto,
        recode_path_to_inlined_dns_link(path),
        path.typ().as_str(),
        target_host,
        content_path.strip_prefix('/').unwrap_or(&content_path)
    ))
}

#[tracing::instrument()]
async fn handle_only_if_cached<T: ContentLoader>(
    request_headers: &HeaderMap,
    state: &State<T>,
    cid: &CidOrDomain,
) -> Result<bool, GatewayError> {
    if request_headers.contains_key(&HEADER_CACHE_CONTROL) {
        let hv = request_headers.get(&HEADER_CACHE_CONTROL).unwrap();
        if hv.to_str().unwrap() == "only-if-cached" {
            return match cid {
                // ToDo: Race is possible if file would have been deleted immediately after the check
                CidOrDomain::Cid(cid) => match state.client.has_file_locally(cid).await {
                    Ok(true) => Ok(true),
                    Ok(false) => Err(GatewayError::new(
                        StatusCode::PRECONDITION_FAILED,
                        "File not found in cache",
                    )),
                    Err(e) => Err(GatewayError::new(
                        StatusCode::PRECONDITION_FAILED,
                        &format!("Error checking cache: {e}"),
                    )),
                },
                CidOrDomain::Domain(_) => Err(GatewayError::new(
                    StatusCode::PRECONDITION_FAILED,
                    "Cannot resolve in cache: invalid CID.",
                )),
            };
        }
    }
    Ok(false)
}

pub async fn check_bad_bits<T: ContentLoader>(
    state: &State<T>,
    cid: &Cid,
    content_path: &str,
) -> bool {
    // check if cid is in the denylist
    if state.bad_bits.is_some() {
        let bad_bits = state.bad_bits.as_ref();
        if let Some(bbits) = bad_bits {
            if bbits.read().await.is_bad(cid, content_path) {
                return true;
            }
        }
    }
    false
}

#[tracing::instrument()]
fn etag_check(
    request_headers: &HeaderMap,
    resolved_cid: &CidOrDomain,
    format: &ResponseFormat,
) -> Option<GatewayResponse> {
    if request_headers.contains_key("If-None-Match") {
        let inm = request_headers
            .get("If-None-Match")
            .unwrap()
            .to_str()
            .unwrap();
        if !inm.is_empty() {
            let cid_etag = get_etag(resolved_cid, Some(format.clone()));
            let dir_etag = get_dir_etag(resolved_cid);

            if etag_matches(inm, &cid_etag) || etag_matches(inm, &dir_etag) {
                return Some(GatewayResponse::not_modified());
            }
        }
    }
    None
}

#[tracing::instrument()]
async fn serve_raw<T: ContentLoader + Unpin>(
    req: &IpfsRequest,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    http_req: &HttpRequest<Body>,
    start_time: time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    let range: Option<Range<u64>> = if http_req.headers().contains_key(RANGE) {
        parse_range_header(http_req.headers().get(RANGE).unwrap())
    } else {
        None
    };
    // FIXME: we currently only retrieve full cids
    let (body, metadata) = state
        .client
        .get_file(
            req.resolved_path.clone(),
            Some(req.path_metadata.clone()),
            start_time,
            range.clone(),
        )
        .await
        .map_err(|e| GatewayError::new(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    match body {
        FileResult::File(body) | FileResult::Raw(body) => {
            let file_name = match req.query_file_name().is_empty() {
                true => format!("{}.bin", req.cid),
                false => req.query_file_name().to_string(),
            };

            set_content_disposition_headers(&mut headers, &file_name, DISPOSITION_ATTACHMENT);
            set_etag_headers(&mut headers, get_etag(&req.cid, Some(req.format.clone())));
            if let Some(res) = etag_check(&headers, &req.cid, &req.format) {
                return Ok(res);
            }
            add_cache_control_headers(&mut headers, &metadata);
            add_ipfs_roots_headers(&mut headers, &metadata);
            add_content_length_header(&mut headers, metadata.size);

            if let Some(mut capped_range) = range {
                if let Some(size) = metadata.size {
                    capped_range.end = std::cmp::min(capped_range.end, size);
                }
                add_etag_range(&mut headers, capped_range.clone());
                add_content_range_headers(&mut headers, capped_range, metadata.size);
                Ok(GatewayResponse::new(
                    StatusCode::PARTIAL_CONTENT,
                    body,
                    headers,
                ))
            } else {
                Ok(GatewayResponse::new(StatusCode::OK, body, headers))
            }
        }
        FileResult::Directory(_) => Err(GatewayError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot serve directory as raw",
        )),
    }
}

#[tracing::instrument()]
async fn serve_car<T: ContentLoader + Unpin>(
    req: &IpfsRequest,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    start_time: time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // TODO: handle car versions
    // FIXME: we currently only retrieve full cids
    let (body, metadata) = state
        .client
        .get_file(
            req.resolved_path.clone(),
            Some(req.path_metadata.clone()),
            start_time,
            None,
        )
        .await
        .map_err(|e| GatewayError::new(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    match body {
        FileResult::File(body) | FileResult::Raw(body) => {
            let file_name = match req.query_file_name().is_empty() {
                true => format!("{}.car", req.cid),
                false => req.query_file_name().to_string(),
            };

            set_content_disposition_headers(&mut headers, &file_name, DISPOSITION_ATTACHMENT);

            add_cache_control_headers(&mut headers, &metadata);
            add_content_length_header(&mut headers, metadata.size);
            let etag = format!("W/{}", get_etag(&req.cid, Some(req.format.clone())));
            set_etag_headers(&mut headers, etag);
            if let Some(res) = etag_check(&headers, &req.cid, &req.format) {
                return Ok(res);
            }
            add_ipfs_roots_headers(&mut headers, &metadata);
            Ok(GatewayResponse::new(StatusCode::OK, body, headers))
        }
        FileResult::Directory(_) => Err(GatewayError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot serve directory as car file",
        )),
    }
}

#[tracing::instrument()]
async fn serve_car_recursive<T: ContentLoader + Unpin>(
    req: &IpfsRequest,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    start_time: time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    let body = state
        .client
        .clone()
        .get_car_recursive(req.resolved_path.clone(), start_time)
        .await
        .map_err(|e| GatewayError::new(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    let file_name = match req.query_file_name().is_empty() {
        true => format!("{}.car", req.cid),
        false => req.query_file_name().to_string(),
    };

    set_content_disposition_headers(&mut headers, &file_name, DISPOSITION_ATTACHMENT);

    // add_cache_control_headers(&mut headers, metadata.clone());
    let etag = format!("W/{}", get_etag(&req.cid, Some(req.format.clone())));
    set_etag_headers(&mut headers, etag);
    if let Some(res) = etag_check(&headers, &req.cid, &req.format) {
        return Ok(res);
    }
    // add_ipfs_roots_headers(&mut headers, metadata);
    Ok(GatewayResponse::new(StatusCode::OK, body, headers))
}

#[tracing::instrument()]
#[async_recursion]
async fn serve_fs<T: ContentLoader + Unpin>(
    req: &IpfsRequest,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    http_req: &HttpRequest<Body>,
    start_time: time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    let range: Option<Range<u64>> = if http_req.headers().contains_key(RANGE) {
        parse_range_header(http_req.headers().get(RANGE).unwrap())
    } else {
        None
    };
    // FIXME: we currently only retrieve full cids
    let (body, metadata) = state
        .client
        .get_file(
            req.resolved_path.clone(),
            Some(req.path_metadata.clone()),
            start_time,
            range.clone(),
        )
        .await
        .map_err(|e| GatewayError::new(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    add_ipfs_roots_headers(&mut headers, &metadata);
    match body {
        FileResult::Directory(res) => {
            let dir_list: anyhow::Result<Vec<_>> = res
                .unixfs_read_dir(&state.client.resolver, OutMetrics { start: start_time })
                .map_err(|e| GatewayError::new(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
                .expect("already known this is a directory")
                .try_collect()
                .await;
            match dir_list {
                Ok(dir_list) => {
                    serve_fs_dir(&dir_list, req, state, headers, http_req, start_time).await
                }
                Err(e) => {
                    tracing::warn!("failed to read dir: {:?}", e);
                    Err(GatewayError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to read dir listing",
                    ))
                }
            }
        }
        FileResult::File(body) => {
            match metadata.unixfs_type {
                Some(_) => {
                    // todo(arqu): error on no size
                    // todo(arqu): add lazy seeking
                    add_cache_control_headers(&mut headers, &metadata);
                    add_content_length_header(
                        &mut headers,
                        range
                            .as_ref()
                            .map(|range| range.end - range.start)
                            .or(metadata.size),
                    );
                    set_etag_headers(&mut headers, get_etag(&req.cid, Some(req.format.clone())));
                    if let Some(res) = etag_check(&headers, &req.cid, &req.format) {
                        return Ok(res);
                    }
                    let name = add_content_disposition_headers(
                        &mut headers,
                        req.query_file_name(),
                        &req.resolved_path,
                        req.query_download(),
                    );
                    if metadata.unixfs_type == Some(UnixfsType::Symlink) {
                        headers.insert(
                            CONTENT_TYPE,
                            HeaderValue::from_str("inode/symlink").unwrap(),
                        );
                    } else {
                        let content_sniffed_mime = body.get_mime();
                        add_content_type_headers(&mut headers, &name, content_sniffed_mime);
                    }
                    if let Some(mut range) = range {
                        if let Some(size) = metadata.size {
                            range.end = std::cmp::min(range.end, size);
                        }
                        add_etag_range(&mut headers, range.clone());
                        add_content_range_headers(&mut headers, range, metadata.size);
                        Ok(GatewayResponse::new(
                            StatusCode::PARTIAL_CONTENT,
                            body,
                            headers,
                        ))
                    } else {
                        Ok(GatewayResponse::new(StatusCode::OK, body, headers))
                    }
                }
                None => Err(GatewayError::new(
                    StatusCode::BAD_REQUEST,
                    "couldn't determine unixfs type",
                )),
            }
        }
        FileResult::Raw(body) => {
            // todo(arqu): error on no size
            // todo(arqu): add lazy seeking
            add_cache_control_headers(&mut headers, &metadata);
            add_content_length_header(
                &mut headers,
                range.map(|range| range.end - range.start).or(metadata.size),
            );
            set_etag_headers(&mut headers, get_etag(&req.cid, Some(req.format.clone())));
            if let Some(res) = etag_check(&headers, &req.cid, &req.format) {
                return Ok(res);
            }
            let name = add_content_disposition_headers(
                &mut headers,
                req.query_file_name(),
                &req.resolved_path,
                req.query_params.download.unwrap_or_default(),
            );
            let content_sniffed_mime = body.get_mime();
            add_content_type_headers(&mut headers, &name, content_sniffed_mime);
            Ok(GatewayResponse::new(StatusCode::OK, body, headers))
        }
    }
}

#[tracing::instrument()]
async fn serve_fs_dir<T: ContentLoader + Unpin>(
    dir_list: &[Link],
    req: &IpfsRequest,
    state: Arc<State<T>>,
    mut headers: HeaderMap,
    http_req: &HttpRequest<Body>,
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
        if !req.resolved_path.has_trailing_slash() {
            let redirect_path = format!(
                "{}{}",
                req.request_path_for_redirection(),
                req.query_params.to_query_string()
            );
            return Ok(GatewayResponse::redirect_permanently(&redirect_path));
        }
        let modified_path = req.resolved_path.with_suffix("index.html");
        let new_req = state
            .client
            .build_ipfs_request(
                &modified_path,
                &req.query_params,
                req.format.clone(),
                req.subdomain_mode,
            )
            .await?;
        return serve_fs(&new_req, state, headers, http_req, start_time).await;
    }

    headers.insert(CONTENT_TYPE, HeaderValue::from_str("text/html").unwrap());
    set_etag_headers(&mut headers, get_dir_etag(&req.cid));
    if let Some(res) = etag_check(&headers, &req.cid, &req.format) {
        return Ok(res);
    }

    let mut template_data: Map<String, Json> = Map::new();
    let mut root_path = req.resolved_path.clone();
    if !root_path.has_trailing_slash() {
        root_path.push("");
    }

    let mut breadcrumbs: Vec<HashMap<&str, String>> = Vec::new();
    root_path
        .to_string()
        .trim_matches('/')
        .split('/')
        .fold(&mut breadcrumbs, |accum, path_el| {
            let mut el = HashMap::new();
            let path = match accum.last() {
                Some(prev) => match prev.get("path") {
                    Some(base) => format!("{}/{}", base, encode(path_el)),
                    None => format!("/{}", encode(path_el)),
                },
                None => {
                    format!("/{}", encode(path_el))
                }
            };
            el.insert("name", path_el.to_string());
            el.insert("path", path);
            accum.push(el);
            accum
        });
    template_data.insert("breadcrumbs".to_string(), json!(breadcrumbs));
    if let CidOrDomain::Cid(root_cid) = req.cid {
        template_data.insert("root_cid".to_string(), Json::String(root_cid.to_string()));
    }

    template_data.insert(
        "root_path".to_string(),
        Json::String(req.resolved_path.to_string()),
    );
    template_data.insert(
        "public_url_base".to_string(),
        Json::String(state.config.public_url_base().to_string()),
    );
    // TODO(b5) - add directory size
    template_data.insert("size".to_string(), Json::String("".to_string()));
    let links = dir_list
        .iter()
        .map(|l| {
            let name = l.name.as_deref().unwrap_or_default();
            let mut link = Map::new();
            link.insert("name".to_string(), Json::String(get_filename(name)));
            link.insert(
                "size".to_string(),
                Json::String(format_bytes(l.tsize.unwrap_or_default())),
            );
            link.insert(
                "path".to_string(),
                Json::String(format!("{root_path}{name}")),
            );
            link.insert("icon".to_string(), Json::String(icon_class_name(name)));
            link
        })
        .collect::<Vec<Map<String, Json>>>();
    template_data.insert("links".to_string(), json!(links));
    let reg = Handlebars::new();
    let dir_template = state.handlebars.get("dir_list").unwrap();
    let res = reg.render_template(dir_template, &template_data).unwrap();
    Ok(GatewayResponse::new(
        StatusCode::OK,
        Body::from(res),
        headers,
    ))
}

// #[tracing::instrument()]
pub async fn request_middleware<B>(
    request: http::Request<B>,
    next: middleware::Next<B>,
) -> axum::response::Response {
    let method = request.method().clone();
    let mut r = next.run(request).await;
    if method == Method::HEAD {
        let b = r.body_mut();
        *b = http_body::combinators::UnsyncBoxBody::default();
    }
    r
}

pub fn maybe_html_error(err: GatewayError, method: Method, headers: HeaderMap) -> GatewayError {
    if headers.contains_key("accept") {
        let accept = headers.get("accept").unwrap().to_str().unwrap();
        if accept.contains("text/html") {
            return err.with_method(method).with_html();
        }
    }
    err.with_method(method)
}

#[tracing::instrument()]
pub async fn middleware_error_handler(
    request_headers: HeaderMap,
    method: Method,
    err: BoxError,
) -> impl IntoResponse {
    inc!(GatewayMetrics::FailCount);
    if err.is::<GatewayError>() {
        let err = err.downcast::<GatewayError>().unwrap();
        return maybe_html_error(*err, method, request_headers);
    }

    if err.is::<tower::timeout::error::Elapsed>() {
        return GatewayError::new(StatusCode::GATEWAY_TIMEOUT, "request timed out");
    }

    if err.is::<tower::load_shed::error::Overloaded>() {
        return GatewayError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "service is overloaded, try again later",
        );
    }

    return GatewayError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("unhandled internal error: {err}").as_str(),
    );
}
