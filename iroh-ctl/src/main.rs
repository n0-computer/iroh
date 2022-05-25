use iroh_rpc_client::{Client, RpcClientConfig};
use tokio::time::{sleep, Duration};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let client = Client::new(&RpcClientConfig::default()).await.unwrap();
    loop {
        let status = client.p2p.check().await.unwrap();
        println!("health: {:?}", status);
        sleep(Duration::from_secs(1)).await;
    }
}
