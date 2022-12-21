use std::env;

use anyhow::Result;
use flatfs_store::Flatfs;
use rocks_store::RocksFs;

fn main() -> Result<()> {
    let mut args = env::args();
    let old_path = args.nth(1).unwrap();
    let new_path = args.next().unwrap();
    let limit: Option<usize> = args.next().and_then(|v| v.parse().ok());

    println!("Importing from {old_path:?} into {new_path:?} (limit: {limit:?})");

    let (mut opts, cache) = rocks_store::default_options();
    opts.set_use_direct_io_for_flush_and_compaction(true);
    opts.set_use_direct_reads(true);
    opts.set_write_buffer_size(512 * 1024 * 1024);
    opts.set_blob_file_size(512 * 1024 * 1024);

    let flatfs = Flatfs::new(old_path)?;
    let rocksfs = RocksFs::with_options(opts, Some(cache), new_path)?;

    let mut count = 0;
    let mut size = 0;

    let buffer_size = 512;
    let mut buffer = Vec::with_capacity(buffer_size);

    for r in flatfs.iter() {
        if let Some(limit) = limit {
            if limit == count {
                break;
            }
        }
        let (key, value) = r?;
        count += 1;
        size += value.len();

        buffer.push((key, value));
        if buffer.len() == buffer_size {
            rocksfs.bulk_put(buffer.iter().map(|(k, v)| (k, v)))?;
            buffer.clear();
        }

        if size % 10_000 == 0 {
            println!("{count} - {size}bytes");
        }
    }

    println!("Imported {count} values, of size {size} bytes");
    let sst_size = rocksfs.sst_files_size()?;
    println!("sst files size: {sst_size}");

    rocksfs.compact();
    println!("Compacted DB");

    let sst_size = rocksfs.sst_files_size()?;
    println!("sst files size: {sst_size}");

    let stats = rocksfs.stats()?;
    println!("{stats}");

    Ok(())
}
