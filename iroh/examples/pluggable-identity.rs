//! Mutually authenticate two direct endpoints with ML-DSA-65 identities.
//!
//! Run with `cargo run -p iroh --example pluggable-identity --features unstable-identity`.

#[cfg(not(wasm_browser))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use iroh::identity::{LocalIdentity, Registry, RemotePolicy};
    use iroh::{Endpoint, endpoint::presets::Empty};
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    tokio::time::timeout(Duration::from_secs(15), async {
        let registry = Arc::new(Registry::builtins(vec![2])?);
        let server = Endpoint::builder(Empty)
            .credentials(
                LocalIdentity::generate_ml_dsa65(&registry)?,
                registry.clone(),
            )
            .remote_policy(RemotePolicy::new([2]))
            .bind_addr("127.0.0.1:0".parse()?)
            .alpns(vec![b"identity-demo/1".to_vec()])
            .bind()
            .await?;
        let client = Endpoint::builder(Empty)
            .credentials(LocalIdentity::generate_ml_dsa65(&registry)?, registry)
            .remote_policy(RemotePolicy::new([2]))
            .bind_addr("127.0.0.1:0".parse()?)
            .bind()
            .await?;
        let start = Instant::now();
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.addr()?, b"identity-demo/1"),
            server.accept()
        );
        let outgoing = outgoing?;
        let incoming = incoming?;
        println!(
            "Mutual ML-DSA-65 authentication completed in {:?}",
            start.elapsed()
        );
        println!("Server authenticated: {}", outgoing.remote_id());
        println!("Client authenticated: {}", incoming.remote_id());
        let mut send = outgoing.open_uni().await?;
        send.write_all(b"hello from a PQ identity").await?;
        send.finish()?;
        let mut recv = incoming.accept_uni().await?;
        println!(
            "Received: {}",
            String::from_utf8(recv.read_to_end(1024).await?)?
        );
        tokio::join!(client.close(), server.close());
        Ok(())
    })
    .await?
}

#[cfg(wasm_browser)]
fn main() {
    eprintln!("The identity endpoint currently supports native targets only.");
}
