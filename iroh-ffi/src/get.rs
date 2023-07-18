use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, ensure, Result};
use bytes::Bytes;
use iroh_io::AsyncSliceWriter;
use safer_ffi::prelude::*;

use iroh::{
    bytes::{
        get::fsm,
        protocol::{AnyGetRequest, GetRequest},
    },
    collection::Collection,
    dial::{dial, Ticket},
};

use crate::{error::IrohError, node::IrohNode};

// #[ffi_export]
// /// @memberof iroh_node_t
// // TODO(b5): optional token arg
// fn iroh_get(
//     node: &IrohNode,
//     hash: char_p::Ref<'_>,
//     peer: char_p::Ref<'_>,
//     peer_addr: char_p::Ref<'_>,
//     out_path: char_p::Ref<'_>,
//     callback: extern "C" fn(Option<repr_c::Box<IrohError>>),
// ) {
//     let node1 = node.inner();
//     let rt = node.async_runtime();
//     let hash = hash.to_string();
//     let peer = peer.to_string();
//     let peer_addr = peer_addr.to_string();
//     let out_path = PathBuf::from(out_path.to_string());

//     rt.spawn(async move {
//         let result = async {
//             let hash = hash.parse::<Hash>()?;
//             let peer = peer.parse::<PeerId>()?;
//             let peer_addr = peer_addr.parse()?;

//             let conn = node1
//                 .dial(&iroh::bytes::protocol::ALPN, peer, &vec![peer_addr])
//                 .await?;
//             get_blob_to_file(conn, hash, None, out_path).await
//         }
//         .await;

//         match result {
//             Ok(()) => rt.spawn_blocking(move || callback(None)),
//             Err(error) => rt.spawn_blocking(move || callback(Some(IrohError::new(error).into()))),
//         };
//     });
// }

#[ffi_export]
/// @memberof iroh_node_t
/// Get a collection from a peer.
pub fn iroh_get_ticket(
    node: &IrohNode,
    ticket: char_p::Ref<'_>,
    out_path: char_p::Ref<'_>,
) -> Option<repr_c::Box<IrohError>> {
    let ticket = ticket.to_string();
    let out_path = PathBuf::from(out_path.to_string());
    let keypair = node.inner().keypair();

    let result: anyhow::Result<_> = node.async_runtime().main().block_on(async move {
        node.async_runtime()
            .local_pool()
            .spawn_pinned(move || async move {
                let ticket = Ticket::from_str(&ticket)?;

                // TODO(b5): pull DerpMap from node, feed into here:
                let dial_opts = ticket.as_get_options(keypair, None);
                let conn = dial(dial_opts).await?;
                get_collection_to_folder(conn, ticket, out_path).await?;
                anyhow::Ok(())
            })
            .await??;
        Ok(())
    });

    as_opt_err(result)
}

fn as_opt_err(res: Result<()>) -> Option<repr_c::Box<IrohError>> {
    match res {
        Ok(()) => None,
        Err(err) => Some(IrohError::new(err).into()),
    }
}

async fn get_collection_to_folder(
    connection: quinn::Connection,
    ticket: Ticket,
    out_path: PathBuf,
) -> Result<()> {
    use fsm::*;

    ensure!(!out_path.is_file(), "out_path must not be a file");
    tokio::fs::create_dir_all(&out_path).await?;

    let request =
        AnyGetRequest::Get(GetRequest::all(ticket.hash())).with_token(ticket.token().cloned());

    let initial = fsm::start(connection, request);

    let connected = initial.next().await?;
    // we assume that the request includes the entire collection
    let (mut next, _root, collection) = {
        let ConnectedNext::StartRoot(sc) = connected.next().await? else {
            bail!("request did not include collection");
        };

        let (done, data) = sc.next().concatenate_into_vec().await?;
        let data = Bytes::from(data);
        let collection = Collection::from_bytes(&data)?;

        (done.next(), data, collection)
    };

    // download all the children
    let mut blobs = collection.blobs().iter();
    let finishing = loop {
        let start = match next {
            EndBlobNext::MoreChildren(start) => start,
            EndBlobNext::Closing(finishing) => break finishing,
        };

        // get the hash of the next blob, or finish if there are no more
        let Some(blob) = blobs.next() else {
            break start.finish();
        };

        let start = start.next(blob.hash);
        let file_path = out_path.join(&blob.name);
        let mut file = iroh_io::File::create(move || std::fs::File::create(&file_path)).await?;

        let done = start.write_all(&mut file).await?;
        file.sync().await?;

        next = done.next();
    };
    let _stats = finishing.next().await?;

    Ok(())
}
