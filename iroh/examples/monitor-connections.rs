use std::{sync::Arc, time::Duration};

use iroh::{
    Endpoint, RelayMode,
    endpoint::{ConnectionInfo, ConnectionMonitor},
};
use n0_error::{Result, StackResultExt, StdResultExt, ensure_any};
use n0_future::task::AbortOnDropHandle;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{Instrument, info, info_span};

const ALPN: &[u8] = b"iroh/test";

#[tokio::main]
async fn main() -> Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let monitor = Monitor::new();
    let server = Endpoint::empty_builder(RelayMode::Disabled)
        .alpns(vec![ALPN.to_vec()])
        .monitor_connections(monitor.clone())
        .bind()
        .instrument(info_span!("server"))
        .await?;
    let server_addr = server.addr();

    let count = 2;

    let client_task = tokio::spawn(
        async move {
            let client = Endpoint::empty_builder(RelayMode::Disabled)
                .bind()
                .instrument(info_span!("client"))
                .await?;
            for _i in 0..count {
                let conn = client.connect(server_addr.clone(), ALPN).await?;
                let mut s = conn.accept_uni().await.anyerr()?;
                let data = s.read_to_end(2).await.anyerr()?;
                ensure_any!(data == b"hi", "unexpected data");
                conn.close(23u32.into(), b"bye");
            }
            client.close().await;
            n0_error::Ok(client)
        }
        .instrument(info_span!("client")),
    );

    let server_task = tokio::spawn(
        async move {
            for _i in 0..count {
                let conn = server
                    .accept()
                    .await
                    .context("server endpoint closed")?
                    .await?;
                let mut s = conn.open_uni().await.anyerr()?;
                s.write_all(b"hi").await.anyerr()?;
                conn.closed().await;
            }
            info!("done");
            server.close().await;
            n0_error::Ok(())
        }
        .instrument(info_span!("server")),
    );
    client_task.await.std_context("client")?.context("client")?;
    server_task.await.std_context("server")?.context("server")?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(monitor);
    Ok(())
}

/// Our connection monitor impl.
///
/// This here only logs connection open and close events via tracing.
/// It could also maintain a datastructure of all connections, or send the stats to some metrics service.
#[derive(Clone)]
struct Monitor {
    tx: UnboundedSender<ConnectionInfo>,
    _task: Arc<AbortOnDropHandle<()>>,
}

impl ConnectionMonitor for Monitor {
    fn on_connection(&self, connection: ConnectionInfo) {
        self.tx.send(connection).ok();
    }
}

impl Monitor {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(Self::run(rx).instrument(info_span!("watcher")));
        Self {
            tx,
            _task: Arc::new(AbortOnDropHandle::new(task)),
        }
    }

    async fn run(mut rx: UnboundedReceiver<ConnectionInfo>) {
        loop {
            tokio::select! {
                Some(conn) = rx.recv() => {
                    let alpn = String::from_utf8_lossy(conn.alpn()).to_string();
                    let remote = conn.remote_id().fmt_short();
                    info!(%remote, %alpn, rtt=?conn.rtt(), "new connection");
                }
                else => break,
            }
        }
    }
}
