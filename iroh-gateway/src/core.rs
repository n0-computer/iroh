use axum::{
    body::{self, BoxBody},
    error_handling::HandleErrorLayer,
    extract::{Extension, Path, Query},
    http::{header::*, StatusCode},
    response::IntoResponse,
    routing::get,
    BoxError, Router,
};
use cid::Cid;
use libp2p::PeerId;
use metrics::increment_counter;
use serde::Deserialize;
use std::{borrow::Cow, collections::HashMap, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use tower::ServiceBuilder;
use tracing::info;

use crate::{
    client::{Client, Request},
    config::Config,
    constants::*,
    error::GatewayError,
    metrics::{get_current_trace_id, METRICS_CNT_REQUESTS_TOTAL},
    response::{GatewayResponse, ResponseFormat},
    rpc,
};

#[derive(Debug)]
pub struct Core {
    state: Arc<State>,
    _rpc_task: JoinHandle<()>,
}

#[derive(Debug)]
pub(crate) struct State {
    config: Config,
    client: Client,
    rpc_client: iroh_rpc_client::Client,
}

#[derive(Debug, Deserialize)]
pub struct GetParams {
    // todo(arqu): swap this for ResponseFormat
    /// specifies the expected format of the response
    format: Option<String>,
    /// specifies the desired filename of the response
    filename: Option<String>,
    /// specifies whether the response should be of disposition inline or attachment
    download: Option<bool>,
}

impl Core {
    pub async fn new(config: Config, store_id: PeerId) -> anyhow::Result<Self> {
        let (rpc_client, rpc_server) = rpc::tcp_rpc(config.rpc.keypair.clone()).await?;

        let rpc_task = tokio::spawn(async move {
            rpc_server.run().await;
        });
        rpc_client.listen(&config.rpc.listen_addr).await?;

        // dial the p2p node
        rpc_client
            .dial("p2p", "/ip4/127.0.0.1/tcp/4401".parse().unwrap(), store_id)
            .await?;

        Ok(Self {
            state: Arc::new(State {
                config,
                client: Client::new(),
                rpc_client,
            }),
            _rpc_task: rpc_task,
        })
    }

    pub async fn serve(self) {
        let app = Router::new()
            .route("/ipfs/:cid", get(get_ipfs))
            .route("/ipfs/:cid/*cpath", get(get_ipfs))
            .layer(Extension(Arc::clone(&self.state)))
            .layer(
                ServiceBuilder::new()
                    // Handle errors from middleware
                    .layer(HandleErrorLayer::new(middleware_error_handler))
                    .load_shed()
                    .concurrency_limit(1024)
                    .timeout(Duration::from_secs(10))
                    .into_inner(),
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
async fn get_ipfs(
    Extension(state): Extension<Arc<State>>,
    Path(params): Path<HashMap<String, String>>,
    Query(query_params): Query<GetParams>,
) -> Result<GatewayResponse, GatewayError> {
    increment_counter!(METRICS_CNT_REQUESTS_TOTAL);
    let start_time = std::time::Instant::now();
    // parse path params
    let cid_param = params.get("cid").unwrap();
    let cid = Cid::try_from(cid_param.clone());
    let cid = match cid {
        Ok(cid) => cid,
        Err(_) => {
            // todo (arqu): improve error handling if possible https://github.com/dignifiedquire/iroh/pull/4#pullrequestreview-953147597
            return Err(error(StatusCode::BAD_REQUEST, "invalid cid"));
        }
    };

    let cpath = "".to_string();
    let cpath = params.get("cpath").unwrap_or(&cpath);
    let full_content_path = format!("/ipfs/{}{}", cid, cpath);
    // parse query params
    let format = if let Some(format) = query_params.format {
        match ResponseFormat::try_from(format.as_str()) {
            Ok(format) => format,
            Err(err) => {
                return Err(error(StatusCode::BAD_REQUEST, &err));
            }
        }
    } else {
        ResponseFormat::Fs
    };
    let query_file_name = query_params.filename.unwrap_or_default();
    let download = query_params.download.unwrap_or_default();

    // init headers
    let mut headers = HashMap::new();
    format.write_headers(&mut headers);
    headers.insert(HEADER_X_IPFS_PATH.to_string(), full_content_path.clone());
    add_user_headers(&mut headers, state.config.headers.clone());

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
        ResponseFormat::Raw => serve_raw(&req, &state, headers, start_time).await,
        ResponseFormat::Car => serve_car(&req, &state, headers, start_time).await,
        ResponseFormat::Html => serve_html(&req, &state, headers, start_time).await,
        ResponseFormat::Fs => serve_fs(&req, &state, headers, start_time).await,
    }
}

#[tracing::instrument()]
async fn serve_raw(
    req: &Request,
    state: &State,
    mut headers: HashMap<String, String>,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let body = state
        .client
        .get_file_by_cid(req.cid, &state.rpc_client, start_time)
        .await
        .unwrap();
    // .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    set_content_disposition_headers(
        &mut headers,
        format!("{}.bin", req.cid).as_str(),
        DISPOSITION_ATTACHMENT,
    );
    response(StatusCode::OK, body::boxed(body), headers)
}

#[tracing::instrument()]
async fn serve_car(
    req: &Request,
    state: &State,
    mut headers: HashMap<String, String>,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let body = state
        .client
        .get_file_by_cid(req.cid, &state.rpc_client, start_time)
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    set_content_disposition_headers(
        &mut headers,
        format!("{}.car", req.cid).as_str(),
        DISPOSITION_ATTACHMENT,
    );
    response(StatusCode::OK, body::boxed(body), headers)
}

#[tracing::instrument()]
async fn serve_html(
    req: &Request,
    state: &State,
    headers: HashMap<String, String>,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let body = state
        .client
        .get_file_by_cid(req.cid, &state.rpc_client, start_time)
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    response(StatusCode::OK, body::boxed(body), headers)
}

#[tracing::instrument()]
async fn serve_fs(
    req: &Request,
    state: &State,
    mut headers: HashMap<String, String>,
    start_time: std::time::Instant,
) -> Result<GatewayResponse, GatewayError> {
    // FIXME: we currently only retrieve full cids
    let body = state
        .client
        .get_file_by_cid(req.cid, &state.rpc_client, start_time)
        .await
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, &e))?;

    let name = add_content_disposition_headers(
        &mut headers,
        &req.query_file_name,
        &req.content_path,
        req.download,
    );
    add_content_type_headers(&mut headers, &name);
    response(StatusCode::OK, body::boxed(body), headers)
}

#[tracing::instrument()]
fn add_user_headers(headers: &mut HashMap<String, String>, user_headers: HashMap<String, String>) {
    headers.extend(user_headers.into_iter());
}

#[tracing::instrument()]
fn add_content_type_headers(headers: &mut HashMap<String, String>, name: &str) {
    let guess = mime_guess::from_path(name);
    let content_type = guess.first_or_octet_stream().to_string();
    headers.insert(CONTENT_TYPE.to_string(), content_type);
}

#[tracing::instrument()]
fn add_content_disposition_headers(
    headers: &mut HashMap<String, String>,
    filename: &str,
    content_path: &str,
    should_download: bool,
) -> String {
    let mut name = get_filename(content_path);
    if !filename.is_empty() {
        name = filename.to_string();
    }
    if !name.is_empty() {
        let disposition = if should_download {
            DISPOSITION_ATTACHMENT
        } else {
            DISPOSITION_INLINE
        };
        set_content_disposition_headers(headers, &name, disposition);
    }
    name
}

#[tracing::instrument()]
fn set_content_disposition_headers(
    headers: &mut HashMap<String, String>,
    filename: &str,
    disposition: &str,
) {
    headers.insert(
        CONTENT_DISPOSITION.to_string(),
        format!("{}; filename={}", disposition, filename),
    );
}

#[tracing::instrument()]
fn get_filename(content_path: &str) -> String {
    content_path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .last()
        .unwrap_or_default()
}

#[tracing::instrument()]
fn response(
    status_code: StatusCode,
    body: BoxBody,
    headers: HashMap<String, String>,
) -> Result<GatewayResponse, GatewayError> {
    Ok(GatewayResponse {
        status_code,
        body,
        headers,
        trace_id: get_current_trace_id().to_string(),
    })
}

#[tracing::instrument()]
fn error(status_code: StatusCode, message: &str) -> GatewayError {
    GatewayError {
        status_code,
        message: message.to_string(),
        trace_id: get_current_trace_id().to_string(),
    }
}

async fn middleware_error_handler(error: BoxError) -> impl IntoResponse {
    if error.is::<tower::timeout::error::Elapsed>() {
        return (StatusCode::REQUEST_TIMEOUT, Cow::from("request timed out"));
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Cow::from("service is overloaded, try again later"),
        );
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Cow::from(format!("unhandled internal error: {}", error)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_user_headers_test() {
        let mut headers = HashMap::new();
        let user_headers = HashMap::from_iter(vec![
            (HEADER_X_IPFS_PATH.to_string(), "QmHeaderPath1".to_string()),
            (HEADER_X_IPFS_PATH.to_string(), "QmHeaderPath2".to_string()),
        ]);
        add_user_headers(&mut headers, user_headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&HEADER_X_IPFS_PATH.to_string()).unwrap(),
            &"QmHeaderPath2".to_string()
        );
    }

    #[test]
    fn add_content_type_headers_test() {
        let mut headers = HashMap::new();
        let name = "test.txt";
        add_content_type_headers(&mut headers, name);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_TYPE.to_string()).unwrap(),
            &"text/plain".to_string()
        );

        let mut headers = HashMap::new();
        let name = "test.RAND_EXT";
        add_content_type_headers(&mut headers, name);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_TYPE.to_string()).unwrap(),
            &CONTENT_TYPE_OCTET_STREAM.to_string()
        );
    }

    #[test]
    fn add_content_disposition_headers_test() {
        // inline
        let mut headers = HashMap::new();
        let filename = "test.txt";
        let content_path = "QmSomeCid";
        let download = false;
        let name = add_content_disposition_headers(&mut headers, filename, content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION.to_string()).unwrap(),
            &"inline; filename=test.txt".to_string()
        );
        assert_eq!(name, "test.txt");

        // attachment
        let mut headers = HashMap::new();
        let filename = "test.txt";
        let content_path = "QmSomeCid";
        let download = true;
        let name = add_content_disposition_headers(&mut headers, filename, content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION.to_string()).unwrap(),
            &"attachment; filename=test.txt".to_string()
        );
        assert_eq!(name, "test.txt");

        // no filename & no content path filename
        let mut headers = HashMap::new();
        let filename = "";
        let content_path = "QmSomeCid";
        let download = true;
        let name = add_content_disposition_headers(&mut headers, filename, content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(name, "QmSomeCid");

        // no filename & with content path filename
        let mut headers = HashMap::new();
        let filename = "";
        let content_path = "QmSomeCid/folder/test.txt";
        let download = true;
        let name = add_content_disposition_headers(&mut headers, filename, content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(name, "test.txt");
    }

    #[test]
    fn set_content_disposition_headers_test() {
        let mut headers = HashMap::new();
        let filename = "test_inline.txt";
        set_content_disposition_headers(&mut headers, filename, DISPOSITION_INLINE);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION.to_string()).unwrap(),
            &"inline; filename=test_inline.txt".to_string()
        );

        let mut headers = HashMap::new();
        let filename = "test_attachment.txt";
        set_content_disposition_headers(&mut headers, filename, DISPOSITION_ATTACHMENT);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION.to_string()).unwrap(),
            &"attachment; filename=test_attachment.txt".to_string()
        );
    }

    #[test]
    fn get_filename_test() {
        assert_eq!(get_filename("QmSomeCid/folder/test.txt"), "test.txt");
        assert_eq!(get_filename("QmSomeCid/folder"), "folder");
        assert_eq!(get_filename("QmSomeCid"), "QmSomeCid");
        assert_eq!(get_filename(""), "");
    }
}
