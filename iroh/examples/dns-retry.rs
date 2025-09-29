use std::time::Duration;

use iroh::dns::DnsResolver;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let resolver_no_reset = DnsResolver::new();
    let resolver_reset = DnsResolver::new();
    loop {
        println!("start lookup");

        resolver_no_reset.clear_cache().await;
        resolver_reset.reset().await;

        lookup("noreset", &resolver_no_reset).await;
        lookup("reset  ", &resolver_reset).await;

        println!("sleep...");
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

#[tracing::instrument("lookup", skip_all, fields(r=%label))]
async fn lookup(label: &str, resolver: &DnsResolver) {
    let res = resolver
        .lookup_ipv4("google.com", Duration::from_secs(1))
        .await;
    match res {
        Ok(mut iter) => println!("[{label}] ok: {:?}", iter.next()),
        Err(err) => println!("[{label}] failed: {err:?}"),
    }
}
