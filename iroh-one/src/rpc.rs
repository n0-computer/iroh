use crate::config::Config;
use anyhow::Result;
use async_trait::async_trait;
use iroh_rpc_client::{P2pClient, StoreClient};
use iroh_rpc_types::{
    gateway_one::{
        gateway::VersionResponse, p2p::*, store::*, GatewayOneGateway as RpcGateway,
        GatewayOneP2p as RpcP2p, GatewayOneServerAddr, GatewayOneStore as RpcStore,
    },
    p2p::{P2pClientAddr, P2pP2p},
    store::{StoreClientAddr, StoreStore},
};
use std::mem::transmute;
use paste::paste;

/// This macro generates the implementation for a service trait in iroh-one. This works
/// by relaying the calls to the "real" client's backend.
/// Use of `transmute` here is safe because we know the structs are the same, but protobuf
/// imports are duplicated in each crate instead of being shared.
macro_rules! relay {
    ($service:ident, $($func:ident: $req:ty => $res:ty),+) => {
        paste! {
            pub struct [<$service:camel One>] {
                client: [<$service:camel Client>],
            }

            impl [<$service:camel One>] {
                pub async fn new(addr: [<$service:camel ClientAddr>]) -> Result<Self> {
                    let client = [<$service:camel Client>]::new(addr).await?;
                    Ok(Self { client })
                }
            }

            #[async_trait]
            impl [<Rpc $service:camel>] for [<$service:camel One>] {
                $(
                    #[tracing::instrument(skip(self))]
                    async fn [<$func:snake>](&self, req: $req) -> Result<$res> {
                        unsafe { transmute(self.client.backend.[<$func:snake>](transmute(req)).await) }
                    }
                )+
            }
        }
    }
}

pub struct GatewayOne {}

impl GatewayOne {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl RpcGateway for GatewayOne {
    #[tracing::instrument(skip(self))]
    async fn version(&self, _: ()) -> Result<VersionResponse> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(VersionResponse { version })
    }
}

relay!(
    Store,
    put: PutRequest => (),
    get: GetRequest => GetResponse,
    has: HasRequest => HasResponse,
    get_links: GetLinksRequest => GetLinksResponse
);

relay!(
    P2p,
    shutdown: () => (),
    fetch_bitswap: BitswapRequest => BitswapResponse,
    fetch_provider: Key => Providers,
    get_listening_addrs: () => GetListeningAddrsResponse,
    get_peers: () => GetPeersResponse,
    peer_connect: ConnectRequest => ConnectResponse,
    peer_disconnect: DisconnectRequest => (),
    gossipsub_add_explicit_peer: GossipsubPeerIdMsg => (),
    gossipsub_all_mesh_peers: () => GossipsubPeersResponse,
    gossipsub_all_peers: () => GossipsubAllPeersResponse,
    gossipsub_mesh_peers: GossipsubTopicHashMsg => GossipsubPeersResponse,
    gossipsub_publish: GossipsubPublishRequest => GossipsubPublishResponse,
    gossipsub_remove_explicit_peer: GossipsubPeerIdMsg => (),
    gossipsub_subscribe: GossipsubTopicHashMsg => GossipsubSubscribeResponse,
    gossipsub_topics: () => GossipsubTopicsResponse,
    gossipsub_unsubscribe: GossipsubTopicHashMsg => GossipsubSubscribeResponse
);

#[cfg(feature = "grpc")]
impl iroh_rpc_types::NamedService for GatewayOne {
    const NAME: &'static str = "gatewayone";
}

pub async fn new(addr: GatewayOneServerAddr, config: &Config) -> Result<()> {
    let store = StoreOne::new(config.rpc_client.store_addr.as_ref().unwrap().clone()).await?;
    let p2p = P2pOne::new(config.rpc_client.p2p_addr.as_ref().unwrap().clone()).await?;
    iroh_rpc_types::gateway_one::serve(addr, GatewayOne::new(), store, p2p).await
}
