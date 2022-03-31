use std::error::Error;
use tokio;

use iroh_rpc::cli_rpc;
use iroh_rpc::database_rpc;
use iroh_rpc::network;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    {
        let cli_keys = network::generate_keys(None);
        let mut cli_client = cli_rpc::new(cli_keys).await?;
        let cli_id = cli_client.peer_id().await;
        let cli_addr = cli_client
            .start_listening("/ip4/0.0.0.0/tcp/0".parse()?)
            .await
            .expect("Listening not to fail.");

        let db_keys = network::generate_keys(None);
        let mut db_client = database_rpc::new(db_keys).await?;
        let db_id = db_client.peer_id().await;
        let db_addr = db_client
            .start_listening("/ip4/0.0.0.0/tcp/0".parse()?)
            .await
            .expect("Listening not to fail.");

        println!("cli_addr: {:?}\ndb_addr: {:?}", cli_addr, db_addr);

        cli_client
            .dial(db_id, db_addr)
            .await
            .expect("CLI could not dial Database");

        let _ = cli_client.ping(db_id).await;
        let _ = db_client.ping(cli_id).await;
    }
    Ok(())
}
