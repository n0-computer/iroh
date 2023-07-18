use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use iroh_io::{AsyncSliceWriter, File};
use range_collections::RangeSet2;
use safer_ffi::prelude::*;

use iroh::{
    bytes::{
        get::fsm,
        protocol::{GetRequest, RangeSpecSeq, Request, RequestToken},
        Hash,
    },
    dial::{dial, Ticket},
    // net::tls::PeerId,
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
                let opts = ticket.as_get_options(keypair, None);
                let conn = dial(opts).await?;
                get_blob_to_file(conn, ticket.hash(), ticket.token().cloned(), out_path).await?;
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

async fn get_blob_to_file(
    conn: quinn::Connection,
    hash: Hash,
    token: Option<RequestToken>,
    out_path: PathBuf,
) -> Result<()> {
    get_blob_ranges_to_file(
        conn,
        hash,
        token,
        RangeSpecSeq::new([RangeSet2::all()]),
        out_path,
    )
    .await
}

// TODO(b5): This currently assumes "all" ranges, needs to be adjusted to honor
// RangeSpecSeq args other than "all"
async fn get_blob_ranges_to_file(
    conn: quinn::Connection,
    hash: Hash,
    token: Option<RequestToken>,
    ranges: RangeSpecSeq,
    out_path: PathBuf,
) -> Result<()> {
    let request = Request::Get(GetRequest::new(hash, ranges)).with_token(token);
    let response = fsm::start(conn, request);
    let connected = response.next().await?;

    let fsm::ConnectedNext::StartRoot(curr) = connected.next().await? else {
                return Ok(())
            };
    let header = curr.next();

    let path = out_path.clone();
    let mut file = File::create(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)
    })
    .await?;

    let (curr, _size) = header.next().await?;
    let _curr = curr.write_all(&mut file).await?;
    file.sync().await?;
    Ok(())
}
