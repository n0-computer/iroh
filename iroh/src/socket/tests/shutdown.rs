use std::{net::UdpSocket, sync::mpsc as blocking_mpsc};

use n0_future::{future::poll_once, task};
use tokio::sync::oneshot;

use super::*;

const WAIT: Duration = Duration::from_secs(10);

struct BlockingGate {
    release: Option<blocking_mpsc::Sender<()>>,
    started: oneshot::Receiver<()>,
    exited: oneshot::Receiver<()>,
}

impl BlockingGate {
    fn spawn<T: Send + 'static>(owner: T) -> (task::JoinHandle<()>, Self) {
        let (release, released) = blocking_mpsc::channel();
        let (started, started_rx) = oneshot::channel();
        let (exited, exited_rx) = oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            let resource = owner;
            started.send(()).ok();
            released.recv().ok();
            drop(resource);
            exited.send(()).ok();
        });
        (
            task,
            Self {
                release: Some(release),
                started: started_rx,
                exited: exited_rx,
            },
        )
    }

    async fn started(&mut self) {
        time::timeout(WAIT, &mut self.started)
            .await
            .unwrap()
            .unwrap();
    }

    async fn release(mut self) {
        self.release.take().unwrap().send(()).unwrap();
        time::timeout(WAIT, &mut self.exited)
            .await
            .unwrap()
            .unwrap();
    }
}

impl Drop for BlockingGate {
    fn drop(&mut self) {
        // An assertion failure must not leave the runtime waiting on a blocked thread.
        if let Some(release) = self.release.take() {
            release.send(()).ok();
        }
    }
}

async fn endpoint() -> EndpointInner {
    let mut rng = rand::rngs::StdRng::seed_from_u64(41);
    let mut options = default_options(&mut rng);
    options.transports = vec![TransportConfig::default_ipv4()];
    EndpointInner::bind(options).await.unwrap()
}

async fn stop_actor_and_drivers(endpoint: &EndpointInner) {
    endpoint.noq_endpoint().close(0u16.into(), b"");
    endpoint.noq_endpoint().wait_all_draining().await;
    endpoint.sock.shutdown.at_endpoint_closed.cancel();
    let task = endpoint.actor_task.lock().unwrap().take();
    if let Some(mut task) = task {
        time::timeout(WAIT, &mut task).await.unwrap().unwrap();
    }
    endpoint.runtime.shutdown().await;
}

#[tokio::test]
async fn slow_socket_actor_is_joined_after_timeout_and_cancelled_waiter() {
    let endpoint = endpoint().await;
    stop_actor_and_drivers(&endpoint).await;
    // Isolate the actor barrier from QUIC and OS close scheduling in this test.
    for socket in &endpoint.ip_sockets {
        socket.close().await;
    }
    let (actor, mut gate) = BlockingGate::spawn(endpoint.noq_endpoint().clone());
    *endpoint.actor_task.lock().unwrap() = Some(AbortOnDropHandle::new(actor));
    gate.started().await;

    tokio::time::pause();
    let mut first = Box::pin(endpoint.close());
    assert!(poll_once(first.as_mut()).await.is_none());
    assert!(endpoint.sock.shutdown.at_close_start.is_cancelled());
    assert!(!endpoint.is_closed());
    tokio::time::advance(Duration::from_millis(101)).await;
    assert!(poll_once(first.as_mut()).await.is_none());
    assert!(!endpoint.is_closed());
    drop(first);

    assert!(endpoint.actor_task.lock().unwrap().is_none());
    assert!(endpoint.close_future.lock().await.is_some());
    let mut resumed = Box::pin(endpoint.close());
    let mut concurrent = Box::pin(endpoint.close());
    assert!(poll_once(resumed.as_mut()).await.is_none());
    assert!(poll_once(concurrent.as_mut()).await.is_none());

    tokio::time::resume();
    gate.release().await;
    time::timeout(WAIT, resumed).await.unwrap();
    time::timeout(WAIT, concurrent).await.unwrap();
    assert!(endpoint.is_closed());
    assert!(endpoint.close_future.lock().await.is_none());
}

#[test]
fn udp_close_job_survives_cancelled_waiter_and_actor_error() {
    for panic_actor in [false, true] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let endpoint = endpoint().await;
            let socket = endpoint.ip_sockets[0].clone();
            let addr = socket.local_addr().unwrap();
            stop_actor_and_drivers(&endpoint).await;

            if panic_actor {
                let (exiting, exited) = oneshot::channel();
                let task = task::spawn(async move {
                    exiting.send(()).unwrap();
                    panic!("endpoint close actor error regression");
                });
                exited.await.unwrap();
                *endpoint.actor_task.lock().unwrap() = Some(AbortOnDropHandle::new(task));
            }

            let (pool_task, mut gate) = BlockingGate::spawn(());
            gate.started().await;
            let mut first = Box::pin(endpoint.close());
            assert!(poll_once(first.as_mut()).await.is_none());
            // netwatch marks its state Closed before the queued libc::close job
            // runs. That state alone must not complete Endpoint::close.
            assert!(socket.is_closed());
            assert!(!endpoint.is_closed());
            assert_eq!(
                UdpSocket::bind(addr).unwrap_err().kind(),
                std::io::ErrorKind::AddrInUse
            );
            drop(first);

            assert!(endpoint.close_future.lock().await.is_some());
            let mut resumed = Box::pin(endpoint.close());
            let mut concurrent = Box::pin(endpoint.close());
            assert!(poll_once(resumed.as_mut()).await.is_none());
            assert!(poll_once(concurrent.as_mut()).await.is_none());
            assert!(!endpoint.is_closed());

            gate.release().await;
            time::timeout(WAIT, pool_task).await.unwrap().unwrap();
            time::timeout(WAIT, resumed).await.unwrap();
            time::timeout(WAIT, concurrent).await.unwrap();
            assert!(endpoint.is_closed());
            assert!(endpoint.close_future.lock().await.is_none());

            // A new owner may claim the address after our close job finishes.
            // Repeated close reports our completed operation, independent of it.
            let new_owner = UdpSocket::bind(addr).unwrap();
            time::timeout(WAIT, endpoint.close()).await.unwrap();
            assert_eq!(new_owner.local_addr().unwrap(), addr);
            assert_eq!(
                UdpSocket::bind(addr).unwrap_err().kind(),
                std::io::ErrorKind::AddrInUse
            );
        });
    }
}

#[tokio::test]
async fn close_releases_udp_socket_while_endpoint_clones_remain() {
    let endpoint = Arc::new(endpoint().await);
    let other = endpoint.clone();
    let addr = endpoint.ip_sockets[0].local_addr().unwrap();
    time::timeout(WAIT, endpoint.close()).await.unwrap();
    assert!(endpoint.is_closed());
    assert!(other.is_closed());
    let new_owner = UdpSocket::bind(addr).unwrap();
    time::timeout(WAIT, other.close()).await.unwrap();
    assert_eq!(new_owner.local_addr().unwrap(), addr);
}
