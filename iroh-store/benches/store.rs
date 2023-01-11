use std::time::Instant;

use cid::multihash::{Code, MultihashDigest};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use iroh_store::{Config, Store};
use tokio::runtime::Runtime;

const RAW: u64 = 0x55;

pub fn put_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_put");
    for value_size in [32, 128, 512, 1024].iter() {
        let value = vec![8u8; *value_size];
        let hash = Code::Sha2_256.digest(&value);
        let key = cid::Cid::new_v1(RAW, hash);

        group.throughput(criterion::Throughput::Bytes(*value_size as u64));
        group.bench_with_input(
            BenchmarkId::new("value_size", *value_size as u64),
            &(key, value),
            |b, (key, value)| {
                let executor = Runtime::new().unwrap();
                let dir = tempfile::tempdir().unwrap();
                let config = Config::new(dir.path().into());
                let store = executor.block_on(async { Store::create(config).await.unwrap() });
                let store_ref = &store;
                b.to_async(&executor)
                    .iter(|| async move { store_ref.put(*key, black_box(value), []).unwrap() });
            },
        );
    }
    group.finish();
}

pub fn get_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_get");
    for value_size in [32, 128, 512, 1024].iter() {
        group.throughput(criterion::Throughput::Bytes(*value_size as u64));
        group.bench_with_input(
            BenchmarkId::new("value_size", *value_size as u64),
            &(),
            |b, _| {
                let executor = Runtime::new().unwrap();
                let dir = tempfile::tempdir().unwrap();
                let config = Config::new(dir.path().into());
                let store = executor.block_on(async { Store::create(config).await.unwrap() });
                let store_ref = &store;
                let keys = executor.block_on(async {
                    let mut keys = Vec::new();
                    for i in 0..1000 {
                        let value = vec![i as u8; *value_size];
                        let hash = Code::Sha2_256.digest(&value);
                        let key = cid::Cid::new_v1(RAW, hash);
                        keys.push(key);
                        store_ref.put(key, &value, []).unwrap();
                    }
                    keys
                });

                let keys_ref = &keys[..];
                b.to_async(&executor).iter_custom(|iters| async move {
                    let l = keys_ref.len();

                    let start = Instant::now();
                    for i in 0..iters {
                        let key = &keys_ref[(i as usize) % l];
                        let res = store_ref.get(key).unwrap().unwrap();
                        black_box(res);
                    }
                    start.elapsed()
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, put_benchmark, get_benchmark);
criterion_main!(benches);
