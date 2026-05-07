use std::{sync::Arc, time::Duration};

use iroh::{
    Endpoint,
    endpoint::{
        AfterHandshakeOutcome, Closed, Connection, EndpointHooks, WeakConnectionHandle, presets,
    },
};
use n0_error::{Result, StackResultExt, StdResultExt, ensure_any};
use n0_future::task::AbortOnDropHandle;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinSet,
};
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
    let server = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .hooks(monitor.clone())
        .bind()
        .instrument(info_span!("server"))
        .await?;
    let server_addr = server.addr();

    let count = 2;

    let client_task = tokio::spawn(
        async move {
            let client = Endpoint::builder(presets::Minimal)
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
                s.finish().anyerr()?;
                conn.closed().await;
            }
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
#[derive(Clone, Debug)]
struct Monitor {
    tx: UnboundedSender<MonitoredConnection>,
    _task: Arc<AbortOnDropHandle<()>>,
}

/// Static info captured at handshake time, paired with a weak handle to the connection.
///
/// We capture `alpn` and `remote_id` at hook time because [`WeakConnectionHandle`] only
/// exposes [`upgrade`] and [`closed`], so reading these fields after the connection has
/// been dropped would otherwise be impossible.
///
/// [`upgrade`]: WeakConnectionHandle::upgrade
/// [`closed`]: WeakConnectionHandle::closed
#[derive(Debug)]
struct MonitoredConnection {
    alpn: Vec<u8>,
    remote_id: iroh::EndpointId,
    handle: WeakConnectionHandle,
}

impl EndpointHooks for Monitor {
    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        let info = MonitoredConnection {
            alpn: conn.alpn().to_vec(),
            remote_id: conn.remote_id(),
            handle: conn.weak_handle(),
        };
        self.tx.send(info).ok();
        AfterHandshakeOutcome::Accept
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

    async fn run(mut rx: UnboundedReceiver<MonitoredConnection>) {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                Some(MonitoredConnection { alpn, remote_id, handle }) = rx.recv() => {
                    let alpn = String::from_utf8_lossy(&alpn).to_string();
                    let remote = remote_id.fmt_short();
                    let rtt = handle.upgrade().and_then(|c| c.paths().iter().map(|p| p.rtt()).min());
                    info!(%remote, %alpn, ?rtt, "new connection");
                    tasks.spawn(async move {
                        match handle.closed().await {
                            Some(Closed { reason, stats, .. }) => {
                                // We have access to the final stats of the connection!
                                info!(%remote, %alpn, ?reason, udp_rx=stats.udp_rx.bytes, udp_tx=stats.udp_tx.bytes, "connection closed");
                            }
                            None => {
                                // The connection was closed before we could register our stats-on-close listener.
                                info!(%remote, %alpn, "connection closed before tracking started");
                            }
                        }
                    }.instrument(tracing::Span::current()));
                }
                Some(res) = tasks.join_next(), if !tasks.is_empty() => res.expect("conn close task panicked"),
                else => break,
            }
            while let Some(res) = tasks.join_next().await {
                res.expect("conn close task panicked");
            }
        }
    }
}
