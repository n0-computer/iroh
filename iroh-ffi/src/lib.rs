use std::{path::PathBuf, str::FromStr};

use ::safer_ffi::prelude::*;
use anyhow::{Context, Result};
use indicatif::{HumanBytes, HumanDuration};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;

use crate::util::Blake3Cid;
use iroh::blobs::{Blob, Collection};
use iroh::get::get_response_machine::{ConnectedNext, EndBlobNext};
use iroh::get::{self, get_data_path, get_missing_range, get_missing_ranges, pathbuf_from_name};
use iroh::protocol::{GetRequest};
use iroh::provider::Ticket;
use iroh::tokio_util::SeekOptimized;
use iroh::{Hash, PeerId};

mod util;

const MAX_CONCURRENT_DIALS: u8 = 16;

#[ffi_export]
fn iroh_get(
    hash: char_p::Ref<'_>,
    peer: char_p::Ref<'_>,
    peer_addr: char_p::Ref<'_>,
    out_path: char_p::Ref<'_>,
) -> u32 {
    let result = std::panic::catch_unwind(|| {
        let hash = hash.to_str().parse::<Hash>().unwrap();
        let peer = peer.to_str().parse::<PeerId>().unwrap();
        let peer_addr = peer_addr.to_str().parse().unwrap();
        let out_path = PathBuf::from_str(out_path.to_str()).unwrap();
        let rt = Runtime::new().unwrap();

        rt.block_on(get_to_dir(
            GetInteractive::Hash {
                hash,
                opts: get::Options {
                    peer_id: Some(peer),
                    addr: peer_addr,
                    keylog: false,
                },
                single: false,
            },
            out_path,
        ))
        .unwrap();
        0
    });
    if result.is_err() {
        eprintln!("error: rust panicked");
        return 1;
    }
    result.unwrap()
}

#[ffi_export]
fn iroh_get_ticket(ticket: char_p::Ref<'_>, out_path: char_p::Ref<'_>) -> u32 {
    let result = std::panic::catch_unwind(|| {
        let ticket = ticket.to_str().parse::<Ticket>().unwrap();
        let out_path = PathBuf::from_str(out_path.to_str()).unwrap();
        let rt = Runtime::new().unwrap();
        rt.block_on(get_to_dir(
            GetInteractive::Ticket {
                ticket,
                keylog: false,
            },
            out_path,
        ))
        .unwrap();
        0
    });
    if result.is_err() {
        eprintln!("error: rust panicked");
        return 1;
    }
    result.unwrap()
}

#[derive(Debug)]
enum GetInteractive {
    Ticket {
        ticket: Ticket,
        keylog: bool,
    },
    Hash {
        hash: Hash,
        opts: get::Options,
        single: bool,
    },
}

impl GetInteractive {
    fn hash(&self) -> Hash {
        match self {
            GetInteractive::Ticket { ticket, .. } => ticket.hash(),
            GetInteractive::Hash { hash, .. } => *hash,
        }
    }

    fn single(&self) -> bool {
        match self {
            GetInteractive::Ticket { .. } => false,
            GetInteractive::Hash { single, .. } => *single,
        }
    }
}

/// Get into a file or directory
async fn get_to_dir(get: GetInteractive, out_dir: PathBuf) -> Result<()> {
    let hash = get.hash();
    let single = get.single();
    println!("Fetching: {}", Blake3Cid::new(hash));
    println!("[1/3] Connecting ...");

    let temp_dir = out_dir.join(".iroh-tmp");
    let (query, collection) = if single {
        let name = Blake3Cid::new(hash).to_string();
        let query = get_missing_range(&get.hash(), name.as_str(), &temp_dir, &out_dir)?;
        (query, vec![Blob { hash, name }])
    } else {
        let (query, collection) = get_missing_ranges(get.hash(), &out_dir, &temp_dir)?;
        (
            query,
            collection.map(|x| x.into_inner()).unwrap_or_default(),
        )
    };

    let init_download_progress = |count: u64, missing_bytes: u64| {
        println!("[3/3] Downloading ...");
        println!(
            "  {} file(s) with total transfer size {}",
            count,
            HumanBytes(missing_bytes)
        );
    };

    // collection info, in case we won't get a callback with is_root
    let collection_info = if collection.is_empty() {
        None
    } else {
        Some((collection.len() as u64, 0))
    };

    let request = GetRequest::new(get.hash(), query).into();
    let response = match get {
        GetInteractive::Ticket { ticket, keylog } => {
            get::run_ticket(&ticket, request, keylog, MAX_CONCURRENT_DIALS).await?
        }
        GetInteractive::Hash { opts, .. } => get::run(request, opts).await?,
    };
    let connected = response.next().await?;
    println!("[2/3] Requesting ...");
    if let Some((count, missing_bytes)) = collection_info {
        init_download_progress(count, missing_bytes);
    }
    let (mut next, collection) = match connected.next().await? {
        ConnectedNext::StartRoot(curr) => {
            tokio::fs::create_dir_all(&temp_dir)
                .await
                .context("unable to create directory {temp_dir}")?;
            tokio::fs::create_dir_all(&out_dir)
                .await
                .context("Unable to create directory {out_dir}")?;
            let curr = curr.next();
            let (curr, collection_data) = curr.concatenate_into_vec().await?;
            let collection = Collection::from_bytes(&collection_data)?;
            init_download_progress(collection.total_entries(), collection.total_blobs_size());
            tokio::fs::write(get_data_path(&temp_dir, hash), collection_data).await?;
            (curr.next(), collection.into_inner())
        }
        ConnectedNext::StartChild(start_child) => {
            (EndBlobNext::MoreChildren(start_child), collection)
        }
        ConnectedNext::Closing(finish) => (EndBlobNext::Closing(finish), collection),
    };
    // read all the children
    let finishing = loop {
        let start = match next {
            EndBlobNext::MoreChildren(sc) => sc,
            EndBlobNext::Closing(finish) => break finish,
        };
        let child_offset = start.child_offset() as usize;
        let blob = match collection.get(child_offset) {
            Some(blob) => blob,
            None => break start.finish(),
        };

        let hash = blob.hash;
        let name = &blob.name;
        let name = if name.is_empty() {
            PathBuf::from(hash.to_string())
        } else {
            pathbuf_from_name(name)
        };
        // pb.set_message(format!("Receiving '{}'...", name.display()));
        // pb.reset();
        let header = start.next(blob.hash);

        let curr = {
            let final_path = out_dir.join(&name);
            let tempname = blake3::Hash::from(hash).to_hex();
            let data_path = temp_dir.join(format!("{}.data.part", tempname));
            let outboard_path = temp_dir.join(format!("{}.outboard.part", tempname));
            let data_file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&data_path)
                .await?;
            let mut data_file = SeekOptimized::new(data_file).into();
            let (curr, size) = header.next().await?;
            // pb.set_length(size);
            let mut outboard_file = if size > 0 {
                let outboard_file = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&outboard_path)
                    .await?;
                let outboard_file = SeekOptimized::new(outboard_file).into();
                Some(outboard_file)
            } else {
                None
            };
            let curr = curr
                .write_all_with_outboard(&mut outboard_file, &mut data_file)
                .await?;
            tokio::fs::create_dir_all(
                final_path
                    .parent()
                    .context("final path should have parent")?,
            )
            .await?;
            // Flush the data file first, it is the only thing that matters at this point
            data_file.into_inner().shutdown().await?;
            // Rename temp file, to target name
            // once this is done, the file is considered complete
            tokio::fs::rename(data_path, final_path).await?;
            if let Some(outboard_file) = outboard_file.take() {
                // not sure if we have to do this
                outboard_file.into_inner().shutdown().await?;
                // delete the outboard file
                tokio::fs::remove_file(outboard_path).await?;
            }
            curr
        };
        next = curr.next();
    };
    let stats = finishing.next().await?;
    tokio::fs::remove_dir_all(temp_dir).await?;
    println!(
        "Transferred {} in {}, {}/s",
        HumanBytes(stats.bytes_read),
        HumanDuration(stats.elapsed),
        HumanBytes((stats.bytes_read as f64 / stats.elapsed.as_secs_f64()) as u64)
    );

    Ok(())
}

#[cfg(test)]
mod tests {

    /// The following test function is necessary for the header generation.
    #[::safer_ffi::cfg_headers]
    #[test]
    fn generate_headers() -> ::std::io::Result<()> {
        ::safer_ffi::headers::builder()
            .to_file("libiroh.h")?
            .generate()
    }

    #[test]
    fn get_ticket_test() {
        // TODO
        // let result = get_ticket();
        // assert_eq!(result, 0);
    }
}
