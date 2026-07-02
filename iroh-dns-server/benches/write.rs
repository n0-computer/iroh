use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use iroh::{
    RelayUrl, SecretKey,
    address_lookup::pkarr::PkarrRelayClient,
    dns::DnsResolver,
    endpoint_info::EndpointInfo,
    tls::{CaTlsConfig, default_provider},
};
use iroh_dns_server::{Server, config::Config};
use rand::RngExt;
use rand_chacha::rand_core::SeedableRng;
use tokio::runtime::Runtime;

const LOCALHOST_PKARR: &str = "http://localhost:8080/pkarr";

fn benchmark_dns_server(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_server_writes");
    group.sample_size(10);
    for iters in [10_u64, 100_u64, 250_u64, 1000_u64].iter() {
        group.throughput(Throughput::Elements(*iters));
        group.bench_with_input(BenchmarkId::from_parameter(iters), iters, |b, &iters| {
            let rt = Runtime::new().unwrap();
            let config = rt.block_on(Config::load("./config.dev.toml")).unwrap();
            let server = rt.block_on(Server::bind(config)).unwrap();

            let tls_config = CaTlsConfig::default()
                .client_config(default_provider())
                .expect("infallible");
            let pkarr_relay = LOCALHOST_PKARR.parse().expect("valid url");
            let pkarr = PkarrRelayClient::new(pkarr_relay, tls_config, DnsResolver::default());
            let relay_url: RelayUrl = "http://localhost:8080".parse().unwrap();
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

            b.iter_custom(|criterion_iters| {
                let signed_packets = (0..criterion_iters * iters)
                    .map(|_| {
                        let secret_key = SecretKey::from_bytes(&rng.random());
                        let endpoint_info = EndpointInfo::new(secret_key.public())
                            .with_relay_url(relay_url.clone());
                        endpoint_info
                            .to_pkarr_signed_packet(&secret_key, 30)
                            .unwrap()
                    })
                    .collect::<Vec<_>>();

                rt.block_on(async {
                    let start = std::time::Instant::now();
                    for signed_packet in &signed_packets {
                        pkarr.publish(signed_packet).await.unwrap();
                    }
                    start.elapsed()
                })
            });

            rt.block_on(async {
                server.shutdown().await.unwrap();
            });
        });
    }
}

criterion_group!(benches, benchmark_dns_server);
criterion_main!(benches);
