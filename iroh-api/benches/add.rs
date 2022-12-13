use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use futures::TryStreamExt;
use iroh_metrics::config::Config as MetricsConfig;
use iroh_resolver::resolver::Resolver;
use iroh_rpc_client::{Client, Config as RpcClientConfig};
use iroh_rpc_types::Addr;
use iroh_store::{Config as StoreConfig, Store};
use iroh_unixfs::{
    chunker::{ChunkerConfig, DEFAULT_CHUNKS_SIZE},
    content_loader::{FullLoader, FullLoaderConfig},
};
use tokio::runtime::Runtime;

use iroh_api::{Api, UnixfsConfig, UnixfsEntry};

fn add_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("unixfs_add_file");
    for file_size in [
        1024,             //  1 KiB
        1024 * 1024,      //  1 MiB (triggers chunking)
        10 * 1024 * 1024, // 10 MiB (triggers chunking)
    ]
    .iter()
    {
        let value = vec![8u8; *file_size];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{}.raw", file_size));
        std::fs::write(&path, value).unwrap();

        group.throughput(criterion::Throughput::Bytes(*file_size as u64));
        group.bench_with_input(
            BenchmarkId::new("file_size", *file_size as u64),
            &path,
            |b, path| {
                let dir = tempfile::tempdir().unwrap();
                let executor = Runtime::new().unwrap();
                let server_addr = Addr::new_mem();
                let client_addr = server_addr.clone();
                let rpc_client = RpcClientConfig {
                    store_addr: Some(client_addr),
                    ..Default::default()
                };

                let config = StoreConfig {
                    path: dir.path().join("db"),
                    rpc_client: rpc_client.clone(),
                    metrics: MetricsConfig::default(),
                };
                let (_task, client, resolver) = executor.block_on(async {
                    let store = Store::create(config).await.unwrap();
                    let task = executor.spawn(async move {
                        iroh_store::rpc::new(server_addr, store).await.unwrap()
                    });
                    // wait for a moment until the transport is setup
                    // TODO: signal this more clearly
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let client = Client::new(rpc_client).await.unwrap();
                    let content_loader = FullLoader::new(
                        client.clone(),
                        FullLoaderConfig {
                            http_gateways: Vec::new(),
                            indexer: None,
                        },
                    )
                    .unwrap();
                    let resolver = Resolver::new(content_loader);

                    (task, client, resolver)
                });
                b.to_async(&executor).iter(|| {
                    let api = Api::from_client_and_resolver(client.clone(), resolver.clone());
                    async move {
                        let entry = UnixfsEntry::from_path(
                            path,
                            UnixfsConfig {
                                wrap: false,
                                chunker: Some(ChunkerConfig::Fixed(DEFAULT_CHUNKS_SIZE)),
                            },
                        )
                        .await
                        .unwrap();
                        let stream = api.add_stream(entry).await.unwrap();

                        let res: Vec<_> = stream.try_collect().await.unwrap();
                        black_box(res)
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, add_benchmark);
criterion_main!(benches);
