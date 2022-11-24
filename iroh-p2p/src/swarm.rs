use std::time::Duration;

use anyhow::Result;
use iroh_rpc_client::Client;
use libp2p::{
    core::{
        self,
        muxing::StreamMuxerBox,
        transport::{Boxed, OrTransport},
    },
    dns,
    identity::Keypair,
    mplex, noise, quic,
    swarm::{derive_prelude::EitherOutput, ConnectionLimits, Executor, SwarmBuilder},
    tcp, websocket,
    yamux::{self, WindowUpdateMode},
    PeerId, Swarm, Transport,
};

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

    let port_reuse = true;
    let connection_timeout = Duration::from_secs(30);

    // TCP
    let tcp_config = tcp::Config::default().port_reuse(port_reuse);
    let tcp_transport = tcp::tokio::Transport::new(tcp_config.clone());

    // Websockets
    let ws_tcp = websocket::WsConfig::new(tcp::tokio::Transport::new(tcp_config));
    let tcp_ws_transport = tcp_transport.or_transport(ws_tcp);

    // Quic
    let quic_config = quic::Config::new(keypair);
    let quic_transport = quic::tokio::Transport::new(quic_config);

    // Noise config for TCP & Websockets
    let auth_config = {
        let dh_keys = noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(keypair)
            .expect("Noise key generation failed");

        noise::NoiseConfig::xx(dh_keys).into_authenticated()
    };

    // Stream muxer config for TCP & Websockets
    let muxer_config = {
        let mut mplex_config = mplex::MplexConfig::new();
        mplex_config.set_max_buffer_size(usize::MAX);

        let mut yamux_config = yamux::YamuxConfig::default();
        yamux_config.set_max_buffer_size(16 * 1024 * 1024); // TODO: configurable
        yamux_config.set_receive_window_size(16 * 1024 * 1024); // TODO: configurable
        yamux_config.set_window_update_mode(WindowUpdateMode::on_receive());
        core::upgrade::SelectUpgrade::new(yamux_config, mplex_config)
    };

    // Enable Relay if enabled
    let (tcp_ws_transport, relay_client) = if config.relay_client {
        let (relay_transport, relay_client) =
            libp2p::relay::v2::client::Client::new_transport_and_behaviour(
                keypair.public().to_peer_id(),
            );

        let transport = OrTransport::new(relay_transport, tcp_ws_transport);
        let transport = transport
            .upgrade(core::upgrade::Version::V1Lazy)
            .authenticate(auth_config)
            .multiplex(muxer_config)
            .timeout(connection_timeout)
            .boxed();

        (transport, Some(relay_client))
    } else {
        let tcp_transport = tcp_ws_transport
            .upgrade(core::upgrade::Version::V1Lazy)
            .authenticate(auth_config)
            .multiplex(muxer_config)
            .boxed();

        (tcp_transport, None)
    };

    // Merge in Quick
    let transport = OrTransport::new(quic_transport, tcp_ws_transport)
        .map(|o, _| match o {
            EitherOutput::First((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            EitherOutput::Second((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
        })
        .boxed();

    // Setup dns resolution

    let dns_cfg = dns::ResolverConfig::cloudflare();
    let dns_opts = dns::ResolverOpts::default();
    let transport = dns::TokioDnsConfig::custom(transport, dns_cfg, dns_opts)
        .unwrap()
        .boxed();

    (transport, relay_client)
}

pub(crate) async fn build_swarm(
    config: &Libp2pConfig,
    keypair: &Keypair,
    rpc_client: Client,
) -> Result<Swarm<NodeBehaviour>> {
    let peer_id = keypair.public().to_peer_id();

    let (transport, relay_client) = build_transport(keypair, config).await;
    let behaviour = NodeBehaviour::new(keypair, config, relay_client, rpc_client).await?;

    let limits = ConnectionLimits::default()
        .with_max_pending_incoming(Some(config.max_conns_pending_in))
        .with_max_pending_outgoing(Some(config.max_conns_pending_out))
        .with_max_established_incoming(Some(config.max_conns_in))
        .with_max_established_outgoing(Some(config.max_conns_out))
        .with_max_established_per_peer(Some(config.max_conns_per_peer));
    let swarm = SwarmBuilder::with_executor(transport, behaviour, peer_id, Tokio)
        .connection_limits(limits)
        .notify_handler_buffer_size(config.notify_handler_buffer_size.try_into()?)
        .connection_event_buffer_size(config.connection_event_buffer_size)
        .dial_concurrency_factor(config.dial_concurrency_factor.try_into().unwrap())
        .build();

    Ok(swarm)
}

struct Tokio;
impl Executor for Tokio {
    fn exec(&self, fut: std::pin::Pin<Box<dyn futures::Future<Output = ()> + Send>>) {
        tokio::task::spawn(fut);
    }
}
