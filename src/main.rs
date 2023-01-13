use std::{
    collections::HashMap,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, bail, ensure, Result};
use bytes::{Bytes, BytesMut};
use clap::{Parser, Subcommand};
use libp2p_core::identity::ed25519::Keypair;
use s2n_quic::{client::Connect, Client, Server};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_DATA_SIZE: usize = 1024 * 1024 * 1024;

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
#[clap(about = "Send data.")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Serve the data from the given path
    #[clap(about = "Serve the data from the given path")]
    Server {
        paths: Vec<PathBuf>,
        #[clap(long, short)]
        /// Optional port, efaults to 4433.
        port: Option<u16>,
    },
    /// Fetch some data
    #[clap(about = "Fetch the data from the hash")]
    Client {
        hash: bao::Hash,
        #[clap(long, short)]
        /// Option address of the server, defaults to 127.0.0.1:4433.
        addr: Option<SocketAddr>,
        #[clap(long, short)]
        /// Option path to save the file, defaults to using the hash as the name.
        out: Option<PathBuf>,
    },
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
struct Request {
    id: u64,
    /// blake3 hash
    name: [u8; 32],
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
struct Response<'a> {
    id: u64,
    #[serde(borrow)]
    data: Res<'a>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
enum Res<'a> {
    NotFound,
    // If found, a stream of bao data is sent as next message.
    Found {
        /// The size of the coming data in bytes, raw content size.
        size: usize,
        outboard: &'a [u8],
    },
}

impl Res<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Found { outboard, .. } => outboard.len(),
            _ => 0,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct ClientOptions {
    pub addr: Option<SocketAddr>,
    pub out: Option<PathBuf>,
}

async fn main_client(hash: bao::Hash, opts: ClientOptions) -> Result<()> {
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

async fn write_lp<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    // send length prefix
    let mut buffer = [0u8; 10];
    let lp = unsigned_varint::encode::u64(data.len() as u64, &mut buffer);
    writer.write_all(lp).await?;

    // write message
    writer.write_all(data).await?;
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct ServerOptions {
    pub port: Option<u16>,
}

async fn main_server(db: Arc<HashMap<bao::Hash, Data>>, opts: ServerOptions) -> Result<()> {
    let keypair = libp2p_core::identity::Keypair::Ed25519(Keypair::generate());
    let server_config = libp2p_tls::make_server_config(&keypair)?;
    let tls = s2n_quic::provider::tls::rustls::Server::from(server_config);
    let limits = s2n_quic::provider::limits::Default::default();
    let port = if let Some(port) = opts.port {
        port
    } else {
        4433
    };
    let addr = format!("127.0.0.1:{port}");
    let mut server = Server::builder()
        .with_tls(tls)?
        .with_io(addr.as_str())?
        .with_limits(limits)?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    println!("\nlistening at: {:#?}", server.local_addr().unwrap());

    while let Some(mut connection) = server.accept().await {
        let db = db.clone();
        tokio::spawn(async move {
            println!("Connection accepted from {:?}", connection.remote_addr());

            while let Ok(Some(stream)) = connection.accept_bidirectional_stream().await {
                let db = db.clone();
                tokio::spawn(async move {
                    println!("Stream opened from {:?}", stream.connection().remote_addr());
                    let (mut reader, mut writer) = stream.split();
                    let mut out_buffer = BytesMut::zeroed(1024);
                    let mut in_buffer = BytesMut::zeroed(1024);

                    // read length prefix
                    while let Ok(size) = unsigned_varint::aio::read_u64(&mut reader).await {
                        // read next message
                        in_buffer.clear();
                        while (in_buffer.len() as u64) < size {
                            reader.read_buf(&mut in_buffer).await.unwrap();
                        }
                        let size = usize::try_from(size).unwrap();

                        // decode next message
                        let request: Request = postcard::from_bytes(&in_buffer[..size]).unwrap();
                        let name = bao::Hash::from(request.name);
                        let (data, piece) = if let Some(data) = db.get(&name) {
                            (
                                Res::Found {
                                    size: data.data.len(),
                                    outboard: &data.outboard,
                                },
                                Some(data.clone()),
                            )
                        } else {
                            (Res::NotFound, None)
                        };

                        let response = Response {
                            id: request.id,
                            data,
                        };

                        if out_buffer.len() < 20 + response.data.len() {
                            out_buffer.resize(20 + response.data.len(), 0u8);
                        }
                        let used = postcard::to_slice(&response, &mut out_buffer).unwrap();

                        if let Err(e) = write_lp(&mut writer, used).await {
                            eprintln!("failed to write response: {:?}", e);
                        }

                        println!("written response of length {}", used.len());

                        if let Some(piece) = piece {
                            println!("writing data {}", piece.data.len());
                            // if we found the data, write it out now
                            if let Err(err) = writer.write_all(&piece.data).await {
                                eprintln!("failed to write data: {:?}", err);
                            }
                            println!("done writing data");
                        }
                    }

                    println!("Disconnected");
                });
            }
        });
    }

    Ok(())
}

#[derive(Clone)]
struct Data {
    /// outboard data from bo
    outboard: Bytes,
    /// actual data
    data: Bytes,
}

async fn create_db(paths: Vec<&Path>) -> Result<Arc<HashMap<bao::Hash, Data>>> {
    println!("Available Data:");

    let mut db = HashMap::new();
    for path in paths {
        ensure!(path.is_file(), "can only transfer blob data");
        let data = tokio::fs::read(path).await?;
        let num = data.len();
        let (outboard, hash) = bao::encode::outboard(&data);

        println!("- {}: {}MiB", hash.to_hex(), num);
        db.insert(
            hash,
            Data {
                outboard: Bytes::from(outboard),
                data: Bytes::from(data),
            },
        );
    }

    Ok(Arc::new(db))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Client { hash, addr, out } => {
            println!("Requesting: {}", hash.to_hex());
            let opts = ClientOptions { addr, out };
            main_client(hash, opts).await?
        }
        Commands::Server { paths, port } => {
            let db = create_db(paths.iter().map(|p| p.as_path()).collect()).await?;
            let opts = ServerOptions { port };
            main_server(db, opts).await?
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use testdir::testdir;

    #[tokio::test]
    async fn basics() -> Result<()> {
        let dir: PathBuf = testdir!();
        let path = dir.join("hello_world");
        tokio::fs::write(&path, "hello world!").await?;
        let db = create_db(vec![&path]).await?;
        let hash = *db.iter().next().unwrap().0;
        tokio::task::spawn(async move {
            main_server(db, Default::default()).await.unwrap();
        });

        let out = dir.join("out");
        let mut opts = ClientOptions::default();
        opts.out = Some(out.clone());
        main_client(hash, opts).await?;
        let got = tokio::fs::read(out).await?;
        let expect = tokio::fs::read(path).await?;
        assert_eq!(expect, got);

        Ok(())
    }
}
