use std::collections::HashMap;

use futures::StreamExt;

use anyhow::Result;
use iroh_rpc_client::{Client, RpcClientConfig, ServiceStatus};

pub(crate) async fn status(watch: bool) -> Result<()> {
    let client = Client::new(&RpcClientConfig::default()).await.unwrap();
    if watch {
        let status_stream = client.watch().await;
        futures::pin_mut!(status_stream);
        while let Some(s) = status_stream.next().await {
            print_status_table(s);
        }
        Ok(())
    } else {
        let s = client.check().await;
        print_status_table(s);
        Ok(())
    }
}

fn print_status_table(statuses: HashMap<String, ServiceStatus>) {
    println!("gateway status: {:?}", statuses.get("gateway").unwrap());
    println!("p2p status: {:?}", statuses.get("p2p").unwrap());
    println!("store status: {:?}", statuses.get("store").unwrap());
    println!();
}
