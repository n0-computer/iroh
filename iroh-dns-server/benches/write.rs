use anyhow::Result;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use iroh::{discovery::pkarr::PkarrRelayClient, dns::node_info::NodeInfo::SecretKey};
use iroh_dns_server::{config::Config, server::Server, ZoneStore};
use tokio::runtime::Runtime;

const LOCALHOST_PKARR: &str = "http://localhost:8080/pkarr";

async fn start_dns_server(config: Config) -> Result<Server> {
    let store = ZoneStore::persistent(Config::signed_packet_store_path()?, Default::default())?;
    Server::spawn(config, store).await
}

fn benchmark_dns_server(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_server_writes");
    group.sample_size(10);
    for iters in [10_u64, 100_u64, 250_u64, 1000_u64].iter() {
        group.throughput(Throughput::Elements(*iters));
        group.bench_with_input(BenchmarkId::from_parameter(iters), iters, |b, &iters| {
            b.iter(|| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async move {
                    let config = Config::load("./config.dev.toml").await.unwrap();
                    let server = start_dns_server(config).await.unwrap();

                    let secret_key = SecretKey::generate();
                    let node_id = secret_key.public();

                    let pkarr_relay = LOCALHOST_PKARR.parse().expect("valid url");
                    let relay_url = Some("http://localhost:8080".parse().unwrap());
                    let pkarr = PkarrRelayClient::new(pkarr_relay);
                    let node_info = NodeInfo::new(node_id, relay_url, Default::default());
                    let signed_packet = node_info.to_pkarr_signed_packet(&secret_key, 30).unwrap();

                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        pkarr.publish(&signed_packet).await.unwrap();
                    }
                    let duration = start.elapsed();

                    server.shutdown().await.unwrap();

                    duration
                })
            });
        });
    }
}

criterion_group!(benches, benchmark_dns_server);
criterion_main!(benches);
