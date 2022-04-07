pub mod behaviour;
pub mod commands;
pub mod core;
pub mod request_response;
pub mod stream;
pub mod streaming;

pub mod database_rpc {
    use crate::commands::{InCommand, OutCommand};
    use crate::core;
    use crate::core::{InboundEvent, Keypair};
    use crate::stream::{Header, OutStream};
    use crate::streaming::StreamingResponseChannel;
    use futures::channel::mpsc;
    use futures::prelude::*;
    use libp2p::core::PeerId;
    use log::debug;
    use tokio::task::spawn;

    pub const CHUNK_SIZE: u64 = 8000;

    // eventually this will be custom for a database process
    pub async fn new(
        id_keys: Keypair,
    ) -> Result<(core::Client, mpsc::Receiver<InboundEvent>), Box<dyn std::error::Error>> {
        let swarm = core::new_swarm(id_keys).await?;

        let (out_sender, out_receiver) = mpsc::channel(0);
        let (in_sender, in_receiver) = mpsc::channel(0);

        let server = core::Server::new(swarm, out_receiver, in_sender);
        spawn(server.run());
        Ok((core::Client::new(out_sender), in_receiver))
    }

    pub fn new_mem(id_keys: Keypair) -> (core::Client, mpsc::Receiver<InboundEvent>) {
        let swarm = core::new_mem_swarm(id_keys);

        let (out_sender, out_receiver) = mpsc::channel(0);
        let (in_sender, in_receiver) = mpsc::channel(0);

        let server = core::Server::new(swarm, out_receiver, in_sender);
        spawn(server.run());
        (core::Client::new(out_sender), in_receiver)
    }
    // todo: not the right name
    // listens for inbound events & handles InCommands
    // should be specific for specific clients
    // should we just have a way to respond to this in the server, rather than send the request
    // to the client to take care of, the way that ping is currently working
    // provide hooks for each InCommand?
    pub async fn provide(
        out_sender: mpsc::Sender<OutCommand>,
        mut in_receiver: mpsc::Receiver<InboundEvent>,
    ) {
        while let Some(InboundEvent { command, channel }) = in_receiver.next().await {
            match command {
                InCommand::DataRequest { peer_id, id, path } => {
                    tokio::task::spawn(handle_data_request(
                        id,
                        peer_id,
                        path,
                        channel,
                        out_sender.clone(),
                    ));
                }
            }
        }
    }

    // So many ways to do this!
    // right now, iterating over the file in chunks & sending each chunk
    // not paying attention to if the packet was acknowledged
    async fn handle_data_request(
        id: u64,
        peer_id: PeerId,
        path: String,
        channel: StreamingResponseChannel,
        mut out_sender: mpsc::Sender<OutCommand>,
    ) {
        debug!(target: "db streaming", "Handling data request");
        let f = std::fs::File::open(&path).expect(
            "TODO: return error if there is a problem with the request or problem opening the file",
        );
        let size = f.metadata().unwrap().len();
        let num_chunks = {
            let mut num_chunks = 0;
            if size % CHUNK_SIZE != 0 {
                num_chunks += 1;
            }
            num_chunks += size / CHUNK_SIZE;
            num_chunks
        };
        let header = Header {
            id,
            chunk_size: CHUNK_SIZE,
            size,
            num_chunks,
        };
        debug!(target: "db streaming", "Sending header response: {:?}", header);
        out_sender
            .send(OutCommand::HeaderResponse {
                header: header.clone(),
                channel,
            })
            .await
            .expect("Sender to not have dropped.");

        let r = std::io::BufReader::new(f);
        let mut stream = OutStream::new(header, peer_id, out_sender.clone(), Box::new(r));

        // TODO: refactor OutStream to handle early cancels
        stream.send_packets().await;
    }
}

pub mod cli_rpc {
    use crate::core;
    use crate::core::Keypair;
    use futures::channel::mpsc;
    use tokio::task::spawn;

    // eventually this will be custom for a cli process
    pub async fn new(id_keys: Keypair) -> Result<core::Client, Box<dyn std::error::Error>> {
        let swarm = core::new_swarm(id_keys).await?;

        let (out_sender, out_receiver) = mpsc::channel(0);
        let (in_sender, _in_receiver) = mpsc::channel(0);

        let server = core::Server::new(swarm, out_receiver, in_sender);
        spawn(server.run());
        Ok(core::Client::new(out_sender))
    }

    // eventually this will be custom for a cli process
    pub fn new_mem(id_keys: Keypair) -> core::Client {
        let swarm = core::new_mem_swarm(id_keys);

        let (out_sender, out_receiver) = mpsc::channel(0);
        let (in_sender, _in_receiver) = mpsc::channel(0);

        let server = core::Server::new(swarm, out_receiver, in_sender);
        spawn(server.run());
        core::Client::new(out_sender)
    }
}
