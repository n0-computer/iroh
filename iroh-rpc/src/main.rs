use clap::{Arg, Command};
use futures::channel::mpsc;
use libp2p::core::multiaddr::multiaddr;
use libp2p::Multiaddr;
use libp2p::{identity, identity::ed25519};
use rand::{thread_rng, Rng};
use std::error::Error;
use std::time::{Instant, SystemTime};
use tokio::spawn;

use iroh_rpc::cli_rpc;
use iroh_rpc::core;
use iroh_rpc::core::InboundEvent;
use iroh_rpc::database_rpc;

pub fn generate_keys(secret_key_seed: Option<u8>) -> identity::Keypair {
    match secret_key_seed {
        Some(seed) => {
            let mut bytes = [0u8; 32];
            bytes[0] = seed;
            let secret_key = ed25519::SecretKey::from_bytes(&mut bytes).unwrap(); // will only ever error if the byte length is incorrect
            identity::Keypair::Ed25519(secret_key.into())
        }
        None => identity::Keypair::generate_ed25519(),
    }
}

struct IPCTestStruct {
    cli_client: core::Client,
    cli_addr: Multiaddr,
    db_client: core::Client,
    db_in_receiver: mpsc::Receiver<InboundEvent>,
    db_addr: Multiaddr,
}

impl IPCTestStruct {
    async fn new() -> Result<IPCTestStruct, Box<dyn Error>> {
        let cli_keys = generate_keys(None);
        let cli_client = cli_rpc::new(cli_keys).await?;
        let cli_addr = "/ip4/0.0.0.0/tcp/0".parse()?;
        let db_keys = generate_keys(None);
        let (db_client, db_in_receiver) = database_rpc::new(db_keys).await?;
        let db_addr = "/ip4/0.0.0.0/tcp/0".parse()?;
        Ok(IPCTestStruct {
            cli_client,
            cli_addr,
            db_client,
            db_in_receiver,
            db_addr,
        })
    }

    fn new_mem() -> IPCTestStruct {
        let cli_keys = generate_keys(None);
        let cli_client = cli_rpc::new_mem(cli_keys);
        let cli_addr = multiaddr![Memory(thread_rng().gen::<u64>())];

        let db_keys = generate_keys(None);
        let (db_client, db_in_receiver) = database_rpc::new_mem(db_keys);
        let db_addr = multiaddr![Memory(thread_rng().gen::<u64>())];
        IPCTestStruct {
            cli_client,
            cli_addr,
            db_client,
            db_in_receiver,
            db_addr,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    {
        let matches = Command::new("iroh-ipc")
            .version("0.0.1")
            .about("quickly test the iroh ipc streaming by sending a file between two processes")
            .arg_required_else_help(true)
            .arg(
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .help("path to the file")
                    .required(true)
                    .takes_value(true),
            )
            .arg(
                Arg::new("transport")
                    .short('t')
                    .long("transport")
                    .help("set the underlying libp2p transport: mem or tcp")
                    .required(true)
                    .takes_value(true),
            )
            .get_matches();

        let transport = matches.value_of("transport").unwrap();
        let path = matches.value_of("file").unwrap();

        if !std::path::Path::new(path).exists() {
            println!("file {} does not exist or cannot be accessed", path);
            std::process::exit(1);
        }

        pretty_env_logger::init();
        let constructor = {
            match transport {
                "mem" => IPCTestStruct::new_mem(),
                "tcp" => IPCTestStruct::new().await?,
                e => panic!("unknown transport type {}", e),
            }
        };
        let IPCTestStruct {
            cli_addr,
            mut cli_client,
            db_addr,
            mut db_client,
            db_in_receiver,
        } = constructor;

        let cli_addr = cli_client
            .start_listening(cli_addr)
            .await
            .expect("Listening not to fail.");
        let cli_id = cli_client.peer_id().await;

        let db_addr = db_client
            .start_listening(db_addr)
            .await
            .expect("Listening not to fail.");

        let db_id = db_client.peer_id().await;
        // allow the db to listen for incoming commands from the network
        // ping violates this pattern and instead pongs directly when the server
        // receives a ping request
        spawn(database_rpc::provide(db_client.sender(), db_in_receiver));

        println!("cli_addr: {:?}\ndb_addr: {:?}\n\n", cli_addr, db_addr);

        cli_client
            .dial(db_id, db_addr)
            .await
            .expect("CLI could not dial Database");
        {
            let sys_time_start = SystemTime::now();
            let wall_time_start = Instant::now();
            match cli_client.get_file(db_id, String::from(path)).await {
                Ok(_) => println!("got file!"),
                Err(e) => println!("oh no: {}", e),
            }
            let sys_time_end = SystemTime::now();
            let wall_time_end = Instant::now();
            let sys_time_duration = sys_time_end
                .duration_since(sys_time_start)
                .unwrap()
                .as_millis();
            let wall_time_duration = wall_time_end.duration_since(wall_time_start).as_millis();

            print!(
                "\n\nsystem time duration: {}ms\nwall time duration: {}ms\n\n",
                sys_time_duration, wall_time_duration
            );
        }

        let _ = cli_client.ping(db_id).await;
        let _ = db_client.ping(cli_id).await;
    }
    Ok(())
}
