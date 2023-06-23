use reqwest::Url;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::hp::{
    derp::{http::ClientBuilder, DerpMap, MeshKey, PacketForwarderHandler},
    key::node::SecretKey,
};

use super::Client;

/// Spawns, connects, and manages special `derp::http::Clients`.
///
/// These clients handled incoming network update notifications from remote
/// `derp::http::Server`s. These servers are used as `PacketForwarder`s for
/// peers to which we are not directly connected.
/// A `mesh_key` is used to ensure the remote server belongs to the same mesh network.
#[derive(Debug)]
pub(crate) struct MeshClients {
    tasks: JoinSet<()>,
    use_https: bool,
    mesh_key: MeshKey,
    server_key: SecretKey,
    derp_map: DerpMap,
    packet_fwd: PacketForwarderHandler<Client>,
    cancel: CancellationToken,
}

impl MeshClients {
    pub(crate) fn new(
        mesh_key: MeshKey,
        server_key: SecretKey,
        derp_map: DerpMap,
        packet_fwd: PacketForwarderHandler<Client>,
        use_https: bool,
    ) -> Self {
        Self {
            tasks: JoinSet::new(),
            cancel: CancellationToken::new(),
            mesh_key,
            server_key,
            derp_map,
            packet_fwd,
            use_https,
        }
    }

    pub(crate) async fn mesh(&mut self) {
        let mut hosts = Vec::new();
        for (_, region) in self.derp_map.regions.iter() {
            for node in region.nodes.iter() {
                hosts.push(node.host_name.clone());
            }
        }
        let scheme = if self.use_https { "https" } else { "http" };
        for host in hosts {
            let url: Url = format!("{scheme}://{host}/derp").parse().unwrap();
            let client = ClientBuilder::new()
                .mesh_key(Some(self.mesh_key))
                .build_with_server_url(self.server_key.clone(), url);

            let packet_forwarder_handler = self.packet_fwd.clone();
            let cancel = self.cancel.clone();
            let server_public_key = self.server_key.public_key();
            self.tasks.spawn(async move {
                if let Err(e) = client
                    .run_mesh_client(server_public_key, packet_forwarder_handler, cancel)
                    .await
                {
                    tracing::warn!("{e:?}");
                }
            });
        }
    }

    pub(crate) async fn shutdown(mut self) {
        self.cancel.cancel();
        self.tasks.shutdown().await
    }
}
