use anyhow::Result;

/// Spawns, connects, and manages special `derp::http::Clients`.
///
/// These clients handled incoming network update notifications from remote
/// `derp::http::Server`s. These servers are used as `PacketForwarder`s for
/// peers to which we are not directly connected.
/// A `mesh_key` is used to ensure the remote server belongs to the same mesh network.
#[derive(Debug)]
pub(crate) struct MeshClients {}

impl MeshClients {
    pub(crate) fn new() -> Self {
        todo!();
    }

    pub(crate) async fn mesh(&mut self) -> Result<()> {
        todo!();
    }

    pub(crate) async fn shutdown(self) -> Result<()> {
        todo!();
    }
}
