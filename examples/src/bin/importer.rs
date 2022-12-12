use std::{path::PathBuf, time::Instant};

use anyhow::{bail, Result};
use bytes::Bytes;
use clap::Parser;
use futures::{stream::TryStreamExt, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use iroh_car::CarReader;
use iroh_rpc_client::{Client, Config as RpcClientConfig};
use par_stream::prelude::*;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    path: PathBuf,
    #[clap(long)]
    limit: Option<usize>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Importing from {:?} (limit: {:?})", args.path, args.limit);

    let rpc_config = RpcClientConfig::default();
    let rpc = Client::new(rpc_config).await?;

    let car_file = tokio::fs::File::open(&args.path).await?;
    let total_size = car_file.metadata().await?.len();

    let car_reader = CarReader::new(car_file).await?;
    let stream = if let Some(limit) = args.limit {
        car_reader.stream().take(limit).boxed()
    } else {
        car_reader.stream().boxed()
    };

    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
            .progress_chars("#>-")
    );

    let start = Instant::now();
    let pb_clone = pb.clone();

    let res: Vec<_> = stream
        .map_err(anyhow::Error::from)
        .try_par_map_unordered(None, move |(cid, data)| {
            move || {
                let data = Bytes::from(data);
                if iroh_util::verify_hash(&cid, &data) == Some(false) {
                    bail!("invalid hash {:?}", cid);
                }
                let links = iroh_unixfs::parse_links(&cid, &data).unwrap_or_default();
                Ok((cid, data, links))
            }
        })
        .try_par_then_unordered(None, move |(cid, data, links)| {
            let rpc = rpc.clone();
            let pb = pb_clone.clone();
            async move {
                let l = data.len();
                rpc.try_store()?.put(cid, data, links).await?;
                pb.inc(l as _);
                Ok(l)
            }
        })
        .try_collect()
        .await?;

    let count = res.len();
    let bytes: usize = res.into_iter().sum();
    pb.finish();

    println!(
        "imported {} elements ({}) in {}s",
        count,
        bytesize::ByteSize::b(bytes as u64).to_string_as(true),
        start.elapsed().as_secs()
    );

    Ok(())
}
