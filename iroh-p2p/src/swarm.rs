use std::time::Duration;

use anyhow::Result;
use libp2p::{
    core::{
        self,
        muxing::StreamMuxerBox,
        transport::{timeout::TransportTimeout, Boxed, OrTransport},
    },
    identity::Keypair,
    mplex, noise,
    swarm::{ConnectionLimits, SwarmBuilder},
    yamux::{self, WindowUpdateMode},
    PeerId, Swarm, Transport,
};
use prometheus_client::registry::Registry;

use crate::{behaviour::NodeBehaviour, Libp2pConfig};

/// Builds the transport stack that LibP2P will communicate over.
async fn build_transport(
    keypair: &Keypair,
    config: &Libp2pConfig,
) -> (
    Boxed<(PeerId, StreamMuxerBox)>,
    Option<libp2p::relay::v2::client::Client>,
) {
    // TODO: make transports configurable

    let transport =
        libp2p::tcp::TokioTcpTransport::new(libp2p::tcp::GenTcpConfig::default().nodelay(true));
    let transport = libp2p::websocket::WsConfig::new(libp2p::tcp::TokioTcpTransport::new(
        libp2p::tcp::GenTcpConfig::default().nodelay(true),
    ))
    .or_transport(transport);

    // TODO: configurable
    let transport = TransportTimeout::new(transport, Duration::from_secs(5));
    let transport = libp2p::dns::TokioDnsConfig::system(transport).unwrap();

    let auth_config = {
        let dh_keys = noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(keypair)
            .expect("Noise key generation failed");

        noise::NoiseConfig::xx(dh_keys).into_authenticated()
    };

    let muxer_config = {
        let mut mplex_config = mplex::MplexConfig::new();
        mplex_config.set_max_buffer_size(usize::MAX);

        let mut yamux_config = yamux::YamuxConfig::default();
        yamux_config.set_max_buffer_size(16 * 1024 * 1024); // TODO: configurable
        yamux_config.set_receive_window_size(16 * 1024 * 1024); // TODO: configurable
        yamux_config.set_window_update_mode(WindowUpdateMode::on_receive());
        core::upgrade::SelectUpgrade::new(yamux_config, mplex_config)
    };

    if config.relay_client {
        let (relay_transport, relay_client) =
            libp2p::relay::v2::client::Client::new_transport_and_behaviour(
                keypair.public().to_peer_id(),
            );

        let transport = OrTransport::new(relay_transport, transport);
        let transport = transport
            .upgrade(core::upgrade::Version::V1Lazy)
            .authenticate(auth_config)
            .multiplex(muxer_config)
            .timeout(Duration::from_secs(20)) // TODO: configurable
            .boxed();

        (transport, Some(relay_client))
    } else {
        let transport = transport
            .upgrade(core::upgrade::Version::V1Lazy)
            .authenticate(auth_config)
            .multiplex(muxer_config)
            .timeout(Duration::from_secs(20)) // TODO: configurable
            .boxed();

        (transport, None)
    }
}

pub(crate) async fn build_swarm(
    config: &Libp2pConfig,
    keypair: &Keypair,
    registry: &mut Registry,
) -> Result<Swarm<NodeBehaviour>> {
    let peer_id = keypair.public().to_peer_id();

    let (transport, relay_client) = build_transport(keypair, config).await;
    let behaviour = NodeBehaviour::new(keypair, config, registry, relay_client).await?;

    let limits = ConnectionLimits::default()
        .with_max_pending_incoming(Some(10)) // TODO: configurable
        .with_max_pending_outgoing(Some(30)) // TODO: configurable
        .with_max_established_incoming(Some(config.target_peer_count))
        .with_max_established_outgoing(Some(config.target_peer_count))
        .with_max_established_per_peer(Some(5)); // TODO: configurable
    let swarm = SwarmBuilder::new(transport, behaviour, peer_id)
        .connection_limits(limits)
        .notify_handler_buffer_size(20.try_into().unwrap()) // TODO: configurable
        .connection_event_buffer_size(128)
        .dial_concurrency_factor(16.try_into().unwrap())
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();

    Ok(swarm)
}
