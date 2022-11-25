use std::{io::Read, path::PathBuf, time::Instant};

use anyhow::Result;
use bytes::Bytes;
use iroh_resolver::{
    chunker::{self, Chunker},
    resolver::{OutMetrics, Path, ResponseClip},
    unixfs_builder::{read_to_vec, stream_to_resolver, FileBuilder},
};

async fn read_fixture(path: impl AsRef<std::path::Path>) -> Result<Vec<u8>> {
    let path = path.as_ref().to_owned();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(path)?;
        let mut decompressed = Vec::new();
        let mut decoder = ruzstd::streaming_decoder::StreamingDecoder::new(&mut file)?;
        decoder.read_to_end(&mut decompressed)?;

        Ok(decompressed)
    })
    .await?
}

const FIXTURE_DIR: &str = "fixtures";

#[derive(Debug)]
struct Param {
    degree: usize,
    chunker: Chunker,
}

#[tokio::test]
#[ignore]
async fn test_dagger_testdata() -> Result<()> {
    let sources = [
        "uicro_1B.zst",
        "uicro_50B.zst",
        "zero_0B.zst",
        "repeat_0.04GiB_174.zst",
        "repeat_0.04GiB_174_1.zst",
        "repeat_0.04GiB_175.zst",
        "repeat_0.04GiB_175_1.zst",
        "large_repeat_1GiB.zst",
        "large_repeat_5GiB.zst",
    ];

    let params = [
        Param {
            degree: 174,
            chunker: Chunker::Fixed(chunker::Fixed::default()),
        },
        Param {
            degree: 174,
            chunker: Chunker::Rabin(Box::new(chunker::Rabin::default())),
        },
    ];

    for source in sources {
        for param in &params {
            println!("== {:?} ==", source);
            println!("Degree: {}", param.degree);
            println!("Chunker: {}", param.chunker);

            let source = PathBuf::from(FIXTURE_DIR).join(source);
            let data = read_fixture(&source).await?;
            let data = Bytes::from(data);

            let start = Instant::now();

            let file = FileBuilder::new()
                .name(source.to_string_lossy().into_owned())
                .chunker(param.chunker.clone())
                .degree(param.degree)
                .content_bytes(data.clone())
                .build()
                .await?;
            let stream = file.encode().await?;
            let (root, resolver) = stream_to_resolver(stream).await?;
            let out = resolver.resolve(Path::from_cid(root)).await?;
            let t =
                read_to_vec(out.pretty(resolver, OutMetrics::default(), ResponseClip::NoClip)?)
                    .await?;

            println!("Root: {}", root);
            println!("Len: {}", data.len());
            println!("Elapsed: {}s", start.elapsed().as_secs_f32());

            // Ensure the data roundtrips
            assert_eq!(t, data);
        }
    }

    Ok(())
}
