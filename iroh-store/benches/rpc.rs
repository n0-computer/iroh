use std::time::Instant;

use bytes::Bytes;
use cid::multihash::{Code, MultihashDigest};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use iroh_rpc_client::{Client, Config as RpcClientConfig};
use iroh_rpc_types::{store::StoreAddr, Addr};
use iroh_store::{Config, Store};
use tokio::runtime::Runtime;

const RAW: u64 = 0x55;

const VALUES: [usize; 4] = [32, 256, 1024, 256 * 1024];
#[derive(Debug, Copy, Clone)]
enum Transport {
    Http2,
    Mem,
}

impl Transport {
    fn new_addr(self) -> (StoreAddr, StoreAddr, Option<tempfile::TempDir>) {
        match self {
            Transport::Http2 => (
                "irpc://127.0.0.1:4001".parse().unwrap(),
                "irpc://127.0.0.1:4001".parse().unwrap(),
                None,
            ),
            Transport::Mem => {
                let a = Addr::new_mem();
                (a.clone(), a, None)
            }
        }
    }
}

pub fn put_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("rpc_store_put");

    let addrs = [Transport::Http2, Transport::Mem];
    for transport in addrs.into_iter() {
        for value_size in VALUES.iter() {
            let value = Bytes::from(vec![8u8; *value_size]);
            let hash = Code::Sha2_256.digest(&value);
            let key = cid::Cid::new_v1(RAW, hash);

            group.throughput(criterion::Throughput::Bytes(*value_size as u64));
            group.bench_with_input(
                BenchmarkId::new(
                    "(transport, value_size)",
                    format!("({transport:?}, {value_size})"),
                ),
                &(key, value),
                |b, (key, value)| {
                    let dir = tempfile::tempdir().unwrap();
                    let executor = Runtime::new().unwrap();
                    let (server_addr, client_addr, _dir) = transport.new_addr();
                    let rpc_client = RpcClientConfig {
                        store_addr: Some(client_addr.clone()),
                        ..Default::default()
                    };
                    let config = Config::with_rpc_addr(dir.path().join("db"), client_addr);
                    let (_task, rpc) = executor.block_on(async {
                        let store = Store::create(config).await.unwrap();
                        let task = executor.spawn(async move {
                            iroh_store::rpc::new(server_addr, store).await.unwrap()
                        });
                        // wait for a moment until the transport is setup
                        // TODO: signal this more clearly
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        let rpc = Client::new(rpc_client).await.unwrap();
                        (task, rpc)
                    });
                    let rpc_ref = &rpc;
                    b.to_async(&executor).iter(|| async move {
                        rpc_ref
                            .try_store()
                            .unwrap()
                            .put(*key, black_box(value.clone()), vec![])
                            .await
                            .unwrap()
                    });
                },
            );
        }
    }
    group.finish();
}

pub fn get_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("rpc_store_get");
    let addrs = [Transport::Http2, Transport::Mem];
    for transport in addrs.into_iter() {
        for value_size in VALUES.iter() {
            group.throughput(criterion::Throughput::Bytes(*value_size as u64));
            group.bench_with_input(
                BenchmarkId::new(
                    "(transport, value_size)",
                    format!("({transport:?}, {value_size})"),
                ),
                &(),
                |b, _| {
                    let executor = Runtime::new().unwrap();
                    let dir = tempfile::tempdir().unwrap();
                    let (server_addr, client_addr, _dir) = transport.new_addr();
                    let rpc_client = RpcClientConfig {
                        store_addr: Some(client_addr.clone()),
                        ..Default::default()
                    };
                    let config = Config::with_rpc_addr(dir.path().join("db"), client_addr);
                    let (_task, rpc) = executor.block_on(async {
                        let store = Store::create(config).await.unwrap();
                        let task = executor.spawn(async move {
                            iroh_store::rpc::new(server_addr, store).await.unwrap()
                        });
                        // wait for a moment until the transport is setup
                        // TODO: signal this more clearly
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        let rpc = Client::new(rpc_client).await.unwrap();
                        (task, rpc)
                    });
                    let rpc_ref = &rpc;
                    let keys = executor.block_on(async {
                        let mut keys = Vec::new();
                        for i in 0..1000 {
                            let value = Bytes::from(vec![i as u8; *value_size]);
                            let hash = Code::Sha2_256.digest(&value);
                            let key = cid::Cid::new_v1(RAW, hash);
                            keys.push(key);
                            rpc_ref
                                .try_store()
                                .unwrap()
                                .put(key, value.clone(), vec![])
                                .await
                                .unwrap();
                        }
                        keys
                    });

                    let keys_ref = &keys[..];
                    b.to_async(&executor).iter_custom(|iters| async move {
                        let l = keys_ref.len();

                        let start = Instant::now();
                        for i in 0..iters {
                            let key = keys_ref[(i as usize) % l];
                            let res = rpc_ref
                                .try_store()
                                .unwrap()
                                .get(key)
                                .await
                                .unwrap()
                                .unwrap();
                            black_box(res);
                        }
                        start.elapsed()
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, put_benchmark, get_benchmark);
criterion_main!(benches);
