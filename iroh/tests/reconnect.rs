use std::time::Duration;

use iroh::{
    endpoint::{BindError, Connection},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, NodeAddr, NodeId, RelayMap, RelayMode, SecretKey, Watcher,
};
use n0_future::time::timeout;
use n0_snafu::{Result, ResultExt};
use rand::SeedableRng;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[cfg(feature = "test-utils")]
#[tokio::test]
// #[traced_test]
async fn can_die_and_reconnect() -> Result {
    tracing_subscriber::fmt::init();

    let max_wait = Duration::from_secs(5);

    #[derive(Debug, Clone)]
    struct TestProtocol(mpsc::Sender<(NodeId, String)>);

    const TEST_ALPN: &[u8] = b"/iroh/test/1";

    impl ProtocolHandler for TestProtocol {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let remote_node_id = connection.remote_node_id()?;
            let mut stream = connection.accept_uni().await?;
            let data = stream
                .read_to_end(64)
                .await
                .map_err(AcceptError::from_err)?;
            let s = String::from_utf8(data).map_err(AcceptError::from_err)?;
            self.0
                .send((remote_node_id, s))
                .await
                .map_err(AcceptError::from_err)?;
            Ok(())
        }
    }

    /// Runs a future in a separate runtime on a separate thread, cancelling everything
    /// abruptly once `cancel` is invoked.
    fn run_in_thread<T: Send + 'static>(
        cancel: CancellationToken,
        fut: impl std::future::Future<Output = T> + Send + 'static,
    ) -> std::thread::JoinHandle<Option<T>> {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move { cancel.run_until_cancelled(fut).await })
        })
    }

    /// Spawns a new client endpoint
    async fn spawn_client(
        secret_key: SecretKey,
        relay_map: RelayMap,
    ) -> Result<Endpoint, BindError> {
        let ep = Endpoint::builder()
            .secret_key(secret_key)
            .relay_mode(RelayMode::Custom(relay_map))
            .insecure_skip_relay_cert_verify(true)
            .bind()
            .await?;
        Ok(ep)
    }

    /// Spawn a server endpoint, sending incoming messages on `tx`.
    async fn spawn_server(
        secret_key: SecretKey,
        relay_map: RelayMap,
        tx: mpsc::Sender<(NodeId, String)>,
    ) -> Result<Router, BindError> {
        let ep = Endpoint::builder()
            .secret_key(secret_key)
            .relay_mode(RelayMode::Custom(relay_map))
            .insecure_skip_relay_cert_verify(true)
            .bind()
            .await?;
        let router = Router::builder(ep)
            .accept(TEST_ALPN, TestProtocol(tx))
            .spawn();
        Ok(router)
    }

    /// Binds an endpoint, connects to `server_addr`, sends a message, and then do nothing until aborted externally.
    async fn connect_once(
        secret_key: SecretKey,
        relay_map: RelayMap,
        server_addr: NodeAddr,
        msg: String,
    ) -> Result {
        let endpoint = spawn_client(secret_key, relay_map).await?;
        info!(node_id = %endpoint.node_id().fmt_short(), "client node spawned");
        let conn = endpoint.connect(server_addr, TEST_ALPN).await?;
        let mut stream = conn.open_uni().await.e()?;
        stream.write_all(msg.as_bytes()).await.e()?;
        stream.finish().e()?;
        std::future::pending::<()>().await;
        Ok(())
    }

    let (relay_map, _relay_url, _guard) = iroh::test_utils::run_relay_server().await.unwrap();
    let mut rng = &mut rand_chacha::ChaCha12Rng::seed_from_u64(1);

    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let (msgs_recv_tx, mut msgs_recv_rx) = tokio::sync::mpsc::channel(3);
    let recv_task = tokio::task::spawn({
        let relay_map = relay_map.clone();
        let secret_key = SecretKey::generate(&mut rng);
        async move {
            let router = spawn_server(secret_key, relay_map, msgs_recv_tx).await?;
            let addr = router.endpoint().node_addr().initialized().await?;
            info!(node_id = %addr.node_id.fmt_short(), "server node spawned");
            addr_tx.send(addr).unwrap();
            std::future::pending::<()>().await;
            Result::<_, n0_snafu::Error>::Ok(())
        }
    });

    let server_addr = addr_rx.await.e()?;

    // spawn a node, send a message, and then abruptly terminate the node ungracefully
    // after the message was received on our receiver node.
    let cancel = CancellationToken::new();
    let client_secret_key = SecretKey::generate(&mut rng);
    info!("spawn client node");
    let join_handle_1 = run_in_thread(
        cancel.clone(),
        connect_once(
            client_secret_key.clone(),
            relay_map.clone(),
            server_addr.clone(),
            "msg1".to_string(),
        ),
    );
    // assert that we received the message on the receiver node.
    let msg = timeout(max_wait, msgs_recv_rx.recv()).await.e()?.unwrap();
    assert_eq!(msg.0, client_secret_key.public());
    assert_eq!(&msg.1, "msg1");
    info!("kill client node");
    cancel.cancel();

    // spawns the node again with the same node id, and send another message
    let cancel = CancellationToken::new();
    info!("respawn client node");
    let join_handle_2 = run_in_thread(
        cancel.clone(),
        connect_once(
            client_secret_key.clone(),
            relay_map.clone(),
            server_addr.clone(),
            "msg2".to_string(),
        ),
    );
    // assert that we received the message on the server node.
    // this means that the reconnect with the same node id worked.
    let msg = timeout(max_wait, msgs_recv_rx.recv()).await.e()?.unwrap();
    assert_eq!(msg.0, client_secret_key.public());
    assert_eq!(&msg.1, "msg2");
    info!("kill client node");
    cancel.cancel();

    info!("kill recv node");
    recv_task.abort();
    assert!(join_handle_1.join().unwrap().is_none());
    assert!(join_handle_2.join().unwrap().is_none());

    Ok(())
}
