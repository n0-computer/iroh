use axum::{
    body::{self, Body, BoxBody, HttpBody},
    error_handling::HandleErrorLayer,
    extract::{Extension, Path, Query},
    http::{header::*, StatusCode},
    response::{IntoResponse, Redirect},
    routing::get,
    BoxError, Router,
};
use bytes::Bytes;
use cid::Cid;
use iroh_rpc_client::Client as RpcClient;
use serde::{Deserialize, Serialize};
use serde_qs;
use std::{
    collections::HashMap,
    error::Error,
    sync::Arc,
    time::{self, Duration},
};
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
    pub metrics: Metrics,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetParams {
    // todo(arqu): swap this for ResponseFormat
    /// specifies the expected format of the response
    format: Option<String>,
    /// specifies the desired filename of the response
    filename: Option<String>,
    /// specifies whether the response should be of disposition inline or attachment
    download: Option<bool>,
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
        let rpc_client = RpcClient::new(&config.rpc.client_config).await?;

        Ok(Self {
            state: Arc::new(State {
                config,
                client: Client::new(&rpc_client),
                rpc_client,
                metrics,
            }),
        })
    }

    pub async fn serve(self) {
        // todo(arqu): ?uri=... https://github.com/ipfs/go-ipfs/pull/7802
        let app = Router::new()
            .route("/ipfs/:cid", get(get_ipfs))
            .route("/ipfs/:cid/*cpath", get(get_ipfs))
            .route("/ipfs/ipfs/:cid", get(redundant_ipfs))
            .route("/ipfs/ipfs/:cid/*cpath", get(redundant_ipfs))
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
async fn redundant_ipfs(
    Path(params): Path<HashMap<String, String>>,
    Query(query_params): Query<GetParams>,
) -> impl IntoResponse {
    let cid = params.get("cid").unwrap();
    let cpath = "".to_string();
    let cpath = params.get("cpath").unwrap_or(&cpath);
    let redirect_path: String = if cpath.is_empty() {
        format!("/ipfs/{}", cid)
    } else {
        format!("/ipfs/{}/{}", cid, cpath)
    };
    let redirect_path = format!("{}{}", redirect_path, query_params.to_query_string());
    Redirect::to(&redirect_path).into_response()
}

#[tracing::instrument()]
async fn get_ipfs(
    Extension(state): Extension<Arc<State>>,
    Path(params): Path<HashMap<String, String>>,
    Query(query_params): Query<GetParams>,
    request_headers: HeaderMap,
) -> Result<GatewayResponse, GatewayError> {
    state.metrics.requests_total.inc();
    let start_time = time::Instant::now();
    // parse path params
    let cid_param = params.get("cid").unwrap();
    let cid = Cid::try_from(cid_param.clone());
    let cpath = "".to_string();
    let cpath = params.get("cpath").unwrap_or(&cpath);

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

    let cid = match cid {
        Ok(cid) => cid,
        Err(_) => {
            // todo (arqu): improve error handling if possible https://github.com/dignifiedquire/iroh/pull/4#pullrequestreview-953147597
            return Err(error(StatusCode::BAD_REQUEST, "invalid cid", &state));
        }
    };
    let full_content_path = format!("/ipfs/{}{}", cid, cpath);

    // todo(arqu): actually plug in a resolver
    let resolved_cid = resolve_cid(&cid).await.unwrap();

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
        let cid_etag = get_etag(&resolved_cid, Some(format.clone()));
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
    // todo(arqu): add X-Ipfs-Roots

    // handle request and fetch data
    let req = Request {
        format,
        cid,
        full_content_path,
        query_file_name,
        content_path: cpath.to_string(),
        download,
    };

    match req.format {
        ResponseFormat::Raw => serve_raw(&req, state, headers, start_time).await,
        ResponseFormat::Car => serve_car(&req, state, headers, start_time).await,
        ResponseFormat::Fs(_) => serve_fs(&req, state, headers, start_time).await,
    }
}

// todo(arqu): flesh out resolving
#[tracing::instrument()]
async fn resolve_cid(cid: &Cid) -> Result<Cid, String> {
    Ok(*cid)
}

#[tracing::instrument()]
async fn serve_raw(
    req: &Request,
    state: Arc<State>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let body = state
        .client
        .get_file(
            &req.full_content_path,
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
    add_cache_control_headers(&mut headers, req.full_content_path.to_string());
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
    let body = state
        .client
        .get_file(
            &req.full_content_path,
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
    response(StatusCode::OK, body, headers)
}

#[tracing::instrument()]
async fn serve_fs(
    req: &Request,
    state: Arc<State>,
    mut headers: HeaderMap,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let body = state
        .client
        .get_file(
            &req.full_content_path,
            &state.rpc_client,
            start_time,
            Arc::clone(&state),
        )
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e, &state))?;

    let name = add_content_disposition_headers(
        &mut headers,
        &req.query_file_name,
        &req.content_path,
        req.download,
    );
    set_etag_headers(&mut headers, get_etag(&req.cid, Some(req.format.clone())));
    add_cache_control_headers(&mut headers, req.full_content_path.to_string());
    add_content_type_headers(&mut headers, &name);
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
