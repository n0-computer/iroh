/// HTTP over UDS support
/// From https://github.com/tokio-rs/axum/blob/1fe45583626a4c9c890cc01131d38c57f8728686/examples/unix-domain-socket/src/main.rs
use axum::extract::connect_info;
use axum::{Router, Server};
use futures::ready;
use hyper::server::accept::Accept;
use iroh_gateway::{core::State, handlers::get_app_routes};
use iroh_unixfs::content_loader::ContentLoader;
use std::path::PathBuf;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::{unix::UCred, UnixListener, UnixStream};

#[derive(Debug)]
pub struct ServerAccept {
    pub uds: UnixListener,
}

impl Accept for ServerAccept {
    type Conn = UnixStream;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let (stream, _addr) = ready!(self.uds.poll_accept(cx))?;
        Poll::Ready(Some(Ok(stream)))
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct UdsConnectInfo {
    peer_addr: Arc<tokio::net::unix::SocketAddr>,
    peer_cred: UCred,
}

impl connect_info::Connected<&UnixStream> for UdsConnectInfo {
    fn connect_info(target: &UnixStream) -> Self {
        let peer_addr = target.peer_addr().unwrap();
        let peer_cred = target.peer_cred().unwrap();

        Self {
            peer_addr: Arc::new(peer_addr),
            peer_cred,
        }
    }
}

pub fn uds_server<T: ContentLoader + std::marker::Unpin>(
    state: Arc<State<T>>,
    path: PathBuf,
) -> Option<
    Server<
        ServerAccept,
        axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, UdsConnectInfo>,
    >,
> {
    let _ = std::fs::remove_file(&path);
    match UnixListener::bind(&path) {
        Ok(uds) => {
            tracing::debug!("Binding to UDS at {}", path.display());
            let app = get_app_routes(&state);
            Some(
                Server::builder(ServerAccept { uds })
                    .serve(app.into_make_service_with_connect_info::<UdsConnectInfo>()),
            )
        }
        Err(err) => {
            tracing::error!(
                "Failed to bind http uds socket at {}: {}",
                path.display(),
                err
            );
            None
        }
    }
}
