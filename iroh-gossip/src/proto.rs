//! Protocol implementation, as a state machine without IO

use std::{fmt, hash::Hash};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

mod hyparview;
mod plumtree;
pub mod state;
pub mod topic;
pub mod util;

#[cfg(test)]
mod tests;

pub use state::{InEvent, Message, OutEvent, State, Timer, TopicId};
pub use topic::{Command, Config, Event, IO};

/// A peer's identifier or address
///
/// The protocol implementation is generic over this trait. When implementing the protocol,
/// a concrete type must be chosen that will then be used throughout the implementation to identify
/// and index individual peers.
///
/// Note that the concrete type will be used in protocol messages. Therefore, implementations of
/// the protocol are only compatible if the same concrete type is supplied for this trait.
///
/// TODO: Rename to `PeerIdT`?
pub trait PeerAddress: Hash + Eq + Copy + fmt::Debug + Serialize + DeserializeOwned {}
impl<T> PeerAddress for T where T: Hash + Eq + Copy + fmt::Debug + Serialize + DeserializeOwned {}

/// Opaque binary data that is transmitted on messages that introduce new peers.
///
/// Implementations may use these bytes to supply addresses or other information needed to connect
/// to a peer that is not included in the peer's [`PeerAddress`].
pub type PeerData = bytes::Bytes;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PeerInfo<PA> {
    pub id: PA,
    pub data: PeerData,
}

impl<PA> From<(PA, PeerData)> for PeerInfo<PA> {
    fn from((id, data): (PA, PeerData)) -> Self {
        Self { id, data }
    }
}

#[cfg(test)]
mod test {

    use std::{env, time::Instant};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use super::{Command, Config, Event, State};
    use crate::proto::{
        tests::{
            assert_synchronous_active, report_round_distribution, sort, Network, Simulator,
            SimulatorConfig,
        },
        TopicId,
    };
    fn setup_logging() {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();
    }

    #[test]
    fn hyparview_smoke() {
        setup_logging();
        // Create a network with 4 nodes and active_view_capacity 2
        let mut config = Config::default();
        config.membership.active_view_capacity = 2;
        let mut network = Network::new(Instant::now());
        for i in 0..4 {
            network.push(State::new(
                i,
                Default::default(),
                config.clone(),
                rand::rngs::OsRng {},
            ));
        }

        let t: TopicId = [0u8; 32].into();

        // Do some joins between nodes 0,1,2
        network.command(0, t, Command::Join(1));
        network.command(0, t, Command::Join(2));
        network.command(1, t, Command::Join(2));
        network.ticks(10);

        // Confirm emitted events
        let actual = network.events_sorted();
        let expected = sort(vec![
            (0, t, Event::NeighborUp(1)),
            (0, t, Event::NeighborUp(2)),
            (1, t, Event::NeighborUp(2)),
            (1, t, Event::NeighborUp(0)),
            (2, t, Event::NeighborUp(0)),
            (2, t, Event::NeighborUp(1)),
        ]);
        assert_eq!(actual, expected);

        // Confirm active connections
        assert_eq!(network.conns(), vec![(0, 1), (0, 2), (1, 2)]);

        // Now let node 3 join node 0.
        // Node 0 is full, so it will disconnect from either node 1 or node 2.
        network.command(3, t, Command::Join(0));
        network.ticks(8);

        // Confirm emitted events. There's two options because whether node 0 disconnects from
        // node 1 or node 2 is random.
        let actual = network.events_sorted();
        eprintln!("actual {actual:?}");
        let expected1 = sort(vec![
            (3, t, Event::NeighborUp(0)),
            (0, t, Event::NeighborUp(3)),
            (0, t, Event::NeighborDown(1)),
            (1, t, Event::NeighborDown(0)),
        ]);
        let expected2 = sort(vec![
            (3, t, Event::NeighborUp(0)),
            (0, t, Event::NeighborUp(3)),
            (0, t, Event::NeighborDown(2)),
            (2, t, Event::NeighborDown(0)),
        ]);
        assert!((actual == expected1) || (actual == expected2));

        // Confirm active connections.
        if actual == expected1 {
            assert_eq!(network.conns(), vec![(0, 2), (0, 3), (1, 2)]);
        } else {
            assert_eq!(network.conns(), vec![(0, 1), (0, 3), (1, 2)]);
        }
        assert!(assert_synchronous_active(&network));
    }

    #[test]
    fn plumtree_smoke() {
        setup_logging();
        let config = Config::default();
        let mut network = Network::new(Instant::now());
        let broadcast_ticks = 12;
        let join_ticks = 12;
        // build a network with 6 nodes
        for i in 0..6 {
            network.push(State::new(
                i,
                Default::default(),
                config.clone(),
                rand::rngs::OsRng {},
            ));
        }

        let t = [0u8; 32].into();

        // connect nodes 1 and 2 to node 0
        (1..3).for_each(|i| network.command(i, t, Command::Join(0)));
        // connect nodes 4 and 5 to node 3
        (4..6).for_each(|i| network.command(i, t, Command::Join(3)));
        // run ticks and drain events
        network.ticks(join_ticks);
        let _ = network.events();
        assert!(assert_synchronous_active(&network));

        // now broadcast a first message
        network.command(1, t, Command::Broadcast(b"hi1".to_vec().into()));
        network.ticks(broadcast_ticks);
        let events = network.events();
        let received = events.filter(|x| matches!(x, (_, _, Event::Received(_))));
        // message should be received by two other nodes
        assert_eq!(received.count(), 2);
        assert!(assert_synchronous_active(&network));

        // now connect the two sections of the swarm
        network.command(2, t, Command::Join(5));
        network.ticks(join_ticks);
        let _ = network.events();
        report_round_distribution(&network);

        // now broadcast again
        network.command(1, t, Command::Broadcast(b"hi2".to_vec().into()));
        network.ticks(broadcast_ticks);
        let events = network.events();
        let received = events.filter(|x| matches!(x, (_, _, Event::Received(_))));
        // message should be received by all 5 other nodes
        assert_eq!(received.count(), 5);
        assert!(assert_synchronous_active(&network));
        report_round_distribution(&network);
    }

    #[test]
    fn big_multiple_sender() {
        setup_logging();
        let mut gossip_config = Config::default();
        gossip_config.broadcast.optimization_threshold = (read_var("OPTIM", 7) as u16).into();
        let config = SimulatorConfig {
            peers_count: read_var("PEERS", 100),
            ..Default::default()
        };
        let rounds = read_var("ROUNDS", 10);
        let mut simulator = Simulator::new(config, gossip_config);
        simulator.init();
        simulator.bootstrap();
        for i in 0..rounds {
            let from = i + 1;
            let message = format!("m{i}").into_bytes().into();
            simulator.gossip_round(from, message)
        }
        simulator.report_round_sums();
    }

    #[test]
    fn big_single_sender() {
        setup_logging();
        let mut gossip_config = Config::default();
        gossip_config.broadcast.optimization_threshold = (read_var("OPTIM", 7) as u16).into();
        let config = SimulatorConfig {
            peers_count: read_var("PEERS", 100),
            ..Default::default()
        };
        let rounds = read_var("ROUNDS", 10);
        let mut simulator = Simulator::new(config, gossip_config);
        simulator.init();
        simulator.bootstrap();
        for i in 0..rounds {
            let from = 2;
            let message = format!("m{i}").into_bytes().into();
            simulator.gossip_round(from, message)
        }
        simulator.report_round_sums();
    }

    fn read_var(name: &str, default: usize) -> usize {
        env::var(name)
            .unwrap_or_else(|_| default.to_string())
            .parse()
            .unwrap()
    }
}
