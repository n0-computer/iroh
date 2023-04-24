use std::{path::PathBuf, str::FromStr};

use ::safer_ffi::prelude::*;
use anyhow::{Context, Result};
use iroh::{get, provider::Ticket, Hash};
use tokio::runtime::Runtime;

const MAX_CONCURRENT_DIALS: u8 = 16;

#[ffi_export]
fn add_numbers(number1: i32, number2: i32) -> i32 {
    let result = std::panic::catch_unwind(|| {
        println!("Hello from rust!");
        number1 + number2
    });
    if result.is_err() {
        eprintln!("error: rust panicked");
        return -1;
    }
    result.unwrap()
}

#[ffi_export]
fn get_ticket(ticket: char_p::Ref<'_>, out_path: char_p::Ref<'_>) -> u32 {
    let result = std::panic::catch_unwind(|| {
        let ticket = ticket.to_str().parse::<Ticket>().unwrap();
        let out_path = PathBuf::from_str(out_path.to_str()).unwrap();
        let rt = Runtime::new().unwrap();
        rt.block_on(get_ticket_internal(ticket, Some(out_path)))
            .unwrap();
        0
    });
    if result.is_err() {
        eprintln!("error: rust panicked");
        return 1;
    }
    result.unwrap()
}

async fn get_ticket_internal(ticket: Ticket, out: Option<PathBuf>) -> Result<()> {
    let on_connected = || async move {
        println!("connected!");
        Ok(())
    };
    let on_collection = |collection: &iroh::blobs::Collection| {
        // let name = collection.name().to_string();
        let total_entries = collection.total_entries();
        let size = collection.total_blobs_size();
        async move {
            println!(
                "downloading collection containing {total_entries} entries totalling {size} bytes"
            );
            Ok(())
        }
    };

    let on_blob = |hash: Hash, mut reader, name: String| {
        let out = &out;
        async move {
            let name = if name.is_empty() {
                hash.to_string()
            } else {
                name
            };

            if let Some(ref outpath) = out {
                tokio::fs::create_dir_all(outpath)
                    .await
                    .context("Unable to create directory {outpath}")?;
                let dirpath = std::path::PathBuf::from(outpath);
                let filepath = dirpath.join(name);

                // Create temp file
                let (temp_file, dup) = tokio::task::spawn_blocking(|| {
                    let temp_file = tempfile::Builder::new()
                        .prefix("iroh-tmp-")
                        .tempfile_in(dirpath)
                        .context("Failed to create temporary output file")?;
                    let dup = temp_file.as_file().try_clone()?;
                    Ok::<_, anyhow::Error>((temp_file, dup))
                })
                .await??;

                let file = tokio::fs::File::from_std(dup);
                let mut file_buf = tokio::io::BufWriter::new(file);
                tokio::io::copy(&mut reader, &mut file_buf).await?;

                // Rename temp file, to target name
                let filepath2 = filepath.clone();
                if let Some(parent) = filepath2.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .context("Unable to create directory {parent}")?;
                }
                println!("writing {:?}", &filepath2);
                tokio::task::spawn_blocking(|| temp_file.persist(filepath2))
                    .await?
                    .context("Failed to write output file")?;
            } else {
                // Write to OUT_WRITER
                let mut stdout = tokio::io::stdout();
                tokio::io::copy(&mut reader, &mut stdout).await?;
            }

            Ok(reader)
        }
    };

    let stats = get::run_ticket(
        &ticket,
        false,
        MAX_CONCURRENT_DIALS,
        on_connected,
        on_collection,
        on_blob,
    )
    .await?;
    // let stats = get::run(hash, token, opts, on_connected, on_collection, on_blob).await?;
    println!("Done in {:?}", stats.elapsed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The following test function is necessary for the header generation.
    #[::safer_ffi::cfg_headers]
    #[test]
    fn generate_headers() -> ::std::io::Result<()> {
        ::safer_ffi::headers::builder()
            .to_file("c/libiroh.h")?
            .generate()
    }

    #[test]
    fn add_numbers_test() {
        let result = add_numbers(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn get_ticket_test() {
        // TODO
        // let result = get_ticket();
        // assert_eq!(result, 0);
    }
}
