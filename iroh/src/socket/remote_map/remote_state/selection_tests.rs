//! Drive the actor between individual noq events so that an Abandoned event
//! cannot accidentally repair the selection before an assertion.

use std::net::{Ipv4Addr, Ipv6Addr};

use iroh_base::SecretKey;
use n0_watcher::Watchable;

use super::*;
use crate::{
    Endpoint,
    endpoint::{Builder, Connection, QuicTransportConfig, presets},
    socket::transports::Addr,
    tls,
};

const ALPN: &[u8] = b"path-selection";
const IDLE_TIMEOUT: Duration = Duration::from_secs(1);

/// Deterministic preference order, including the empty selection when no
/// candidate matches or the current path is already the best one.
#[derive(Debug)]
struct Prefer(Vec<Addr>);

impl PathSelector for Prefer {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let mut selection = PathSelection::none();
        if let Some(path) = self
            .0
            .iter()
            .find_map(|addr| ctx.paths().find(|p| p.network_path().remote() == *addr))
            && Some(path.network_path()) != ctx.current()
        {
            selection.set(&path);
        }
        selection
    }
}

fn endpoint(key: &SecretKey) -> Builder {
    Endpoint::builder(presets::Minimal)
        .secret_key(key.clone())
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .bind_addr((Ipv6Addr::LOCALHOST, 0))
        .unwrap()
        .alpns(vec![ALPN.to_vec()])
        .transport_config(
            QuicTransportConfig::builder()
                .max_idle_timeout(Some(IDLE_TIMEOUT.try_into().unwrap()))
                .keep_alive_interval(Duration::from_millis(100))
                .build(),
        )
}

/// Dial directly and let the test register the resulting connection with the actor.
async fn connect(client: &Endpoint, server: &Endpoint) -> (noq::Connection, noq::Connection) {
    let client = client.inner().unwrap();
    let addr = server
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .unwrap();
    let config = &client.static_config;
    let dial = client
        .noq_endpoint()
        .connect_with(
            config
                .create_client_config(vec![ALPN.to_vec()], config.transport_config.to_inner_arc()),
            addr,
            &tls::name::encode(server.id()),
        )
        .unwrap();
    let server = server.inner().unwrap();
    let (client, server) = tokio::join!(dial, async {
        server.noq_endpoint().accept().await.unwrap().await.unwrap()
    });
    (client.unwrap(), server)
}

struct Handover {
    actor: RemoteStateActor,
    old: noq::Connection,
    new: noq::Connection,
    peer: noq::Connection,
    connection: Connection,
    v6: SocketAddr,
    _old_peer: noq::Connection,
    _endpoints: [Endpoint; 3],
}

impl Handover {
    async fn new(select_v6: bool) -> Self {
        Self::with_transport(select_v6, |builder, _| builder).await
    }

    async fn with_transport(
        select_v6: bool,
        configure: impl Fn(Builder, EndpointId) -> Builder,
    ) -> Self {
        let key = SecretKey::generate();
        let client_key = SecretKey::generate();
        let client = configure(endpoint(&client_key), client_key.public())
            .bind()
            .await
            .unwrap();
        let old_peer = endpoint(&key).bind().await.unwrap();
        let new_peer = configure(endpoint(&key), key.public())
            .bind()
            .await
            .unwrap();
        let (old, old_remote) = connect(&client, &old_peer).await;
        let (new, peer) = connect(&client, &new_peer).await;
        let old_addr = Addr::from(old.path(PathId::ZERO).unwrap().remote_address().unwrap());
        let v6 = new_peer
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv6)
            .unwrap();
        let mut order = vec![old_addr.clone()];
        if select_v6 {
            order.push(Addr::Ip(v6));
        }
        let mut actor = RemoteStateActor::new(
            new_peer.id(),
            Watchable::new(BTreeSet::new()).watch(),
            client.inner().unwrap().mapped_addrs.clone(),
            Default::default(),
            Default::default(),
            Arc::new(Prefer(order)),
        );
        let (tx, _rx) = oneshot::channel();
        actor.handle_msg_add_connection(old.clone(), tx);
        let (tx, rx) = oneshot::channel();
        actor.handle_msg_add_connection(new.clone(), tx);
        let connection = Connection::for_test(new.clone(), rx.await.unwrap());
        assert_eq!(
            actor.state.selected_path.as_ref().unwrap().remote(),
            old_addr
        );
        Self {
            actor,
            old,
            new,
            peer,
            connection,
            v6,
            _old_peer: old_remote,
            _endpoints: [client, old_peer, new_peer],
        }
    }

    fn preferred(&self) -> Option<Addr> {
        self.actor
            .state
            .selected_path
            .as_ref()
            .map(transports::FourTuple::remote)
    }

    async fn open(&mut self, addr: Addr, status: PathStatus) -> noq::Path {
        let tuple = self
            .actor
            .state
            .mapped_addrs
            .to_mapped_tuple(&transports::FourTuple::from_remote(addr));
        let path = time::timeout(Duration::from_secs(3), async {
            loop {
                match self.new.open_path(tuple, status).await {
                    Err(PathError::RemoteCidsExhausted) => {
                        time::sleep(Duration::from_millis(10)).await
                    }
                    result => break result.unwrap(),
                }
            }
        })
        .await
        .unwrap();
        self.process_event(
            |event| matches!(event, NoqPathEvent::Established { id, .. } if *id == path.id()),
        )
        .await;
        path
    }

    async fn process_event(&mut self, matches: impl Fn(&NoqPathEvent) -> bool) {
        time::timeout(Duration::from_secs(3), async {
            loop {
                let (id, event) = self.actor.state.path_events.next().await.unwrap();
                let done = id == ConnId(self.new.stable_id()) && matches(event.as_ref().unwrap());
                self.actor.handle_path_event(id, event);
                if done {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    async fn close_old(&mut self) {
        self.old.close(0u32.into(), b"handover");
        let (id, closed) = self.actor.state.connections_close.next().await.unwrap();
        assert_eq!(id, ConnId(self.old.stable_id()));
        self.actor.handle_connection_close(id, closed);
    }
}

#[tokio::test]
async fn client_keeps_an_established_ip_during_handover() {
    let mut handover = Handover::new(true).await;
    let best = handover
        .open(Addr::Ip(handover.v6), PathStatus::Backup)
        .await;
    // No Abandoned event is processed between applications. A client can
    // already have a third, unvalidated path to the old port inside noq.
    let old = handover.preferred().unwrap();
    let closing = handover
        .connection
        .paths()
        .get(PathId::ZERO)
        .unwrap()
        .remote_addr()
        .clone();
    let TransportAddr::Ip(closing) = closing else {
        panic!("expected IPv4 path")
    };
    handover.actor.state.path_selector = Arc::new(Prefer(vec![old, Addr::Ip(closing)]));
    handover.actor.select_path();
    handover.actor.state.path_selector = Arc::new(Prefer(Vec::new()));
    handover.actor.select_path();
    handover.actor.apply_selected_path();
    assert_eq!(best.status().unwrap(), PathStatus::Available);
    assert!(
        handover
            .connection
            .paths()
            .get(best.id())
            .unwrap()
            .is_selected()
    );
    handover
        .process_event(|event| {
            matches!(
                event,
                NoqPathEvent::Abandoned {
                    id: PathId::ZERO,
                    ..
                }
            )
        })
        .await;
    assert_eq!(handover.connection.paths().len(), 1);

    time::sleep(IDLE_TIMEOUT + Duration::from_millis(100)).await;
    time::timeout(IDLE_TIMEOUT, async {
        let mut stream = handover.connection.open_uni().await.unwrap();
        stream.write_all(b"still here").await.unwrap();
        stream.finish().unwrap();
        let mut recv = handover.peer.accept_uni().await.unwrap();
        assert_eq!(recv.read_to_end(32).await.unwrap(), b"still here");
    })
    .await
    .expect("data stopped flowing on the selected IP path");
}

#[tokio::test]
async fn close_reselects_the_remaining_connection() {
    let mut handover = Handover::new(false).await;
    let best = handover
        .open(Addr::Ip(handover.v6), PathStatus::Backup)
        .await;
    assert!(handover.connection.paths().iter().all(|p| !p.is_selected()));
    handover.actor.state.path_selector = Arc::new(Prefer(vec![Addr::Ip(handover.v6)]));
    handover.close_old().await;
    assert_eq!(handover.preferred().unwrap(), Addr::Ip(handover.v6));
    assert!(
        handover
            .connection
            .paths()
            .get(best.id())
            .unwrap()
            .is_selected()
    );
    assert_eq!(best.status().unwrap(), PathStatus::Available);
}

#[tokio::test]
async fn empty_selection_clears_dead_preference_and_preserves_open_paths() {
    let mut handover = Handover::new(false).await;
    handover
        .open(Addr::Ip(handover.v6), PathStatus::Available)
        .await;
    handover.close_old().await;
    assert!(handover.actor.state.selected_path.is_none());
    let paths = handover.connection.paths();
    assert_eq!(paths.len(), 2);
    for path in paths.iter() {
        assert!(!path.is_selected());
        assert_eq!(
            handover.new.path(path.id()).unwrap().status().unwrap(),
            PathStatus::Available
        );
    }
    assert_eq!(
        handover.actor.connections[&ConnId(handover.new.stable_id())]
            .open_paths()
            .count(),
        2
    );
}

#[tokio::test]
async fn duplicate_ip_tuples_keep_one_selected_path_id() {
    let mut handover = Handover::new(false).await;
    let addr = Addr::from(
        handover
            .new
            .path(PathId::ZERO)
            .unwrap()
            .remote_address()
            .unwrap(),
    );
    let duplicate = handover.open(addr.clone(), PathStatus::Available).await;
    let old = handover.preferred().unwrap();
    handover.actor.state.path_selector = Arc::new(Prefer(vec![old, addr]));
    handover.actor.select_path();
    handover.actor.apply_selected_path();
    handover
        .process_event(
            |event| matches!(event, NoqPathEvent::Abandoned { id, .. } if *id == duplicate.id()),
        )
        .await;
    let paths = handover.connection.paths();
    assert_eq!(paths.len(), 1);
    assert!(paths.get(PathId::ZERO).unwrap().is_selected());
}

#[cfg(feature = "unstable-custom-transports")]
#[tokio::test]
async fn local_selector_can_prefer_custom_and_keep_an_ip_backup() {
    use crate::test_utils::test_transport::{TestNetwork, to_custom_addr};

    let network = TestNetwork::new();
    let mut handover = Handover::with_transport(false, |builder, id| {
        builder.add_custom_transport(network.create_transport(id).unwrap())
    })
    .await;
    let v6 = handover
        .open(Addr::Ip(handover.v6), PathStatus::Available)
        .await;
    let custom = Addr::Custom(to_custom_addr(handover.actor.state.endpoint_id));
    let old = handover.preferred().unwrap();
    handover.actor.state.path_selector = Arc::new(Prefer(vec![old.clone(), custom.clone()]));
    let chosen = handover.open(custom.clone(), PathStatus::Backup).await;
    handover.actor.apply_selected_path();

    handover
        .process_event(
            |event| matches!(event, NoqPathEvent::Abandoned { id, .. } if *id == v6.id()),
        )
        .await;
    assert_eq!(handover.preferred().unwrap(), old);
    let paths = handover.connection.paths();
    assert_eq!(paths.len(), 2);
    assert!(paths.get(chosen.id()).unwrap().is_selected());
    assert_eq!(chosen.status().unwrap(), PathStatus::Available);
    assert_eq!(
        handover.new.path(PathId::ZERO).unwrap().status().unwrap(),
        PathStatus::Backup
    );

    // Abandon the peer preference while both connections remain open. Neither
    // the peer nor the local selector may retain the vanished custom path.
    handover.actor.state.path_selector = Arc::new(Prefer(vec![custom.clone()]));
    handover.actor.select_path();
    assert_eq!(handover.preferred(), Some(custom));
    chosen.close().unwrap();
    handover
        .process_event(
            |event| matches!(event, NoqPathEvent::Abandoned { id, .. } if *id == chosen.id()),
        )
        .await;
    assert_eq!(handover.preferred(), None);
    assert!(handover.connection.paths().iter().all(|p| !p.is_selected()));
}
