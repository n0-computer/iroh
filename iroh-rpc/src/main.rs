// use libp2p::core::multiaddr::multiaddr;
// use rand::{thread_rng, Rng};
use std::error::Error;
use std::time::{Instant, SystemTime};
use tokio::spawn;

use iroh_rpc::cli_rpc;
use iroh_rpc::database_rpc;
use libp2p::{identity, identity::ed25519};

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    {
        pretty_env_logger::init();
        let cli_keys = generate_keys(None);
        let mut cli_client = cli_rpc::new(cli_keys).await?;
        let cli_addr = cli_client
            .start_listening("/ip4/0.0.0.0/tcp/0".parse()?)
            .await
            .expect("Listening not to fail.");
        // let mut cli_client = cli_rpc::new_mem(cli_keys);
        // let addr = multiaddr![Memory(thread_rng().gen::<u64>())];
        // let cli_addr = cli_client
        //     .start_listening(addr)
        //     .await
        //     .expect("Listening not to fail.");
        let cli_id = cli_client.peer_id().await;

        let db_keys = generate_keys(None);
        let (mut db_client, db_in_receiver) = database_rpc::new(db_keys).await?;
        let db_addr = db_client
            .start_listening("/ip4/0.0.0.0/tcp/0".parse()?)
            .await
            .expect("Listening not to fail.");

        // let (mut db_client, db_in_receiver) = database_rpc::new_mem(db_keys);
        // let addr = multiaddr![Memory(thread_rng().gen::<u64>())];
        // let db_addr = db_client
        //     .start_listening(addr)
        //     .await
        //     .expect("Listening not to fail.");

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
            match cli_client
                .get_file(
                    db_id,
                    String::from("/Users/ramfox/Work/NZ/iroh/iroh-rpc/test_data/1GB.zip"),
                )
                .await
            {
                Ok(_) => println!("got file!"),
                Err(e) => println!("oh no: {}", e),
            }
            let sys_time_end = SystemTime::now();
            let wall_time_end = Instant::now();
            let sys_time_duration = sys_time_end
                .duration_since(sys_time_start)
                .unwrap()
                .as_secs();
            let wall_time_duration = wall_time_end.duration_since(wall_time_start).as_secs();

            print!(
                "\n\nsystem time duration: {}s\nwall time duration: {}s\n\n",
                sys_time_duration, wall_time_duration
            );
        }

        let _ = cli_client.ping(db_id).await;
        let _ = db_client.ping(cli_id).await;
    }
    Ok(())
}
