use std::{io::Read, net::SocketAddr, path::PathBuf, time::Instant};

use anyhow::{anyhow, bail, ensure, Result};
use bytes::BytesMut;
use libp2p_core::identity::ed25519::Keypair;
use s2n_quic::{client::Connect, Client};
use tokio::io::AsyncReadExt;

use crate::protocol::{write_lp, Request, Res, Response};

const MAX_DATA_SIZE: usize = 1024 * 1024 * 1024;

#[derive(Clone, Default, Debug)]
pub struct Options {
    pub addr: Option<SocketAddr>,
    pub out: Option<PathBuf>,
}

pub async fn run(hash: bao::Hash, opts: Options) -> Result<()> {
    let keypair = libp2p_core::identity::Keypair::Ed25519(Keypair::generate());

    let client_config = libp2p_tls::make_client_config(&keypair, None)?;
    let tls = s2n_quic::provider::tls::rustls::Client::from(client_config);

    let client = Client::builder()
        .with_tls(tls)?
        .with_io("0.0.0.0:0")?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    let addr = if let Some(addr) = opts.addr {
        addr
    } else {
        "127.0.0.1:4433".parse().unwrap()
    };
    let connect = Connect::new(addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await?;

    connection.keep_alive(true)?;

    let now = Instant::now();
    let stream = connection.open_bidirectional_stream().await?;
    let (mut reader, mut writer) = stream.split();

    let req = Request {
        id: 1,
        name: hash.into(),
    };

    let mut out_buffer = BytesMut::zeroed(15 + req.name.len());
    let used = postcard::to_slice(&req, &mut out_buffer)?;

    write_lp(&mut writer, used).await?;

    // read response
    {
        let mut in_buffer = BytesMut::zeroed(1024);

        // read length prefix
        let size = unsigned_varint::aio::read_u64(&mut reader).await.unwrap();

        // read next message
        in_buffer.clear();
        while (in_buffer.len() as u64) < size {
            reader.read_buf(&mut in_buffer).await?;
        }
        let response_size = usize::try_from(size).unwrap();
        let response: Response = postcard::from_bytes(&in_buffer[..response_size])?;
        println!("read response of size {}", response_size);
        match response.data {
            Res::Found { size, outboard } => {
                // Need to read the message now
                println!("size is {}", size);
                ensure!(
                    size <= MAX_DATA_SIZE,
                    "size too large: {} > {}",
                    size,
                    MAX_DATA_SIZE
                );

                let outboard = outboard.to_vec();

                let pb = indicatif::ProgressBar::new(size as u64);
                let mut wrapped_reader = pb.wrap_async_read(reader);

                // TODO: avoid buffering

                // remove response buffered data
                let _ = in_buffer.split_to(response_size);
                while in_buffer.len() < size {
                    wrapped_reader.read_buf(&mut in_buffer).await?;
                }

                println!("received data {} bytes", in_buffer.len());
                assert_eq!(
                    size,
                    in_buffer.len(),
                    "expected {} bytes, got {} bytes",
                    size,
                    in_buffer.len()
                );

                let mut decoder = bao::decode::Decoder::new_outboard(
                    std::io::Cursor::new(&in_buffer[..]),
                    &*outboard,
                    &hash,
                );

                {
                    // Ignore the output, not needed
                    let mut buf = [0u8; 1024];
                    while decoder.read(&mut buf)? > 0 {}
                }

                let outpath = if let Some(out) = opts.out {
                    out
                } else {
                    // default to name as hash
                    std::path::PathBuf::from(hash.to_string())
                };
                tokio::fs::write(outpath, in_buffer).await?;
                // print stats
                let data_len = size;
                let elapsed = now.elapsed().as_millis();
                let elapsed_s = elapsed as f64 / 1000.;
                let data_len_bit = data_len * 8;
                let mbits = data_len_bit as f64 / (1000. * 1000.) / elapsed_s;
                pb.println(format!(
                    "Data size: {}MiB\nTime Elapsed: {:.4}s\n{:.2}MBit/s",
                    data_len / 1024 / 1024,
                    elapsed_s,
                    mbits
                ));
            }
            Res::NotFound => {
                bail!("data not found");
            }
        }
    }

    Ok(())
}
