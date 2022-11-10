//! Test the LRU cache implementation.
//!
//! These are a few simple tests of the operations we do on empty and full caches.  Mostly
//! how populated the cache is doesn't seem to affect things much.
//!
//! # Running the benchmarks
//!
//! You can run the benchmarks either by directly using cargo:
//!
//! ```shell
//!    cargo bench -p iroh-p2p
//! ```
//!
//! Or by installing `cargo-criterion`, which gives you slightly prettier output:
//!
//! ```shell
//! cargo install cargo-criterion
//! ```
//!
//! Run the benchmarks:
//!
//! ```shell
//! cargo criterion -p iroh-p2p
//! ```

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use libp2p::PeerId;

/// The size of the cache to make.
///
/// Taken from behaviour::peer_manager::DEFAULT_BAD_PEER_CAP, but that's not `pub` (nor does
/// it need to be).
const CACHE_SIZE: usize = 10 * 4096;

fn bench_contains_empty(c: &mut Criterion) {
    let mut group = c.benchmark_group("Contains, almost empty cache");
    group.bench_function("lru", |bencher| {
        bencher.iter_batched(
            // setup
            || {
                let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
                let peer = PeerId::random();
                cache.put(peer, ());
                for _ in 0..16 {
                    cache.put(PeerId::random(), ());
                }
                let missing = PeerId::random();
                assert!(cache.contains(&peer));
                assert!(!cache.contains(&missing));
                (cache, peer, missing)
            },
            // routine
            |(cache, peer, missing)| {
                cache.contains(&peer);
                cache.contains(&missing);
                cache // drop outside of routine
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_contains_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("Contains, full cache");
    group.bench_function("lru", |bencher| {
        bencher.iter_batched(
            // setup
            || {
                let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
                for _ in 0..CACHE_SIZE {
                    cache.put(PeerId::random(), ());
                }
                let peer = PeerId::random();
                cache.put(peer, ());
                let missing = PeerId::random();
                assert!(cache.contains(&peer));
                assert!(!cache.contains(&missing));
                (cache, peer, missing)
            },
            // routine
            |(cache, peer, missing)| {
                cache.contains(&peer);
                cache.contains(&missing);
                cache // drop outside of routine
            },
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

fn bench_put_empty(c: &mut Criterion) {
    let mut group = c.benchmark_group("put, almost empty cache");
    group.bench_function("lru", |bencher| {
        bencher.iter_batched(
            // setup
            || {
                let cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
                let peer_id = PeerId::random();
                (cache, peer_id)
            },
            // routine
            |(mut cache, peer_id)| {
                cache.put(peer_id, ());
                (cache, peer_id) // drop outside of routine
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_put_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("put, full cache");
    group.bench_function("lru", |bencher| {
        bencher.iter_batched(
            // setup
            || {
                let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
                for _ in 0..CACHE_SIZE {
                    cache.put(PeerId::random(), ());
                }
                let peer_id = PeerId::random();
                (cache, peer_id)
            },
            // routine
            |(mut cache, peer_id)| {
                cache.put(peer_id, ());
                (cache, peer_id) // drop outside of routine
            },
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

fn bench_pop_empty(c: &mut Criterion) {
    let mut group = c.benchmark_group("pop, almost empty cache");
    group.bench_function("lru", |benches| {
        benches.iter_batched(
            // setup
            || {
                let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
                for _ in 0..16 {
                    cache.put(PeerId::random(), ());
                }
                let peer_id = PeerId::random();
                cache.put(peer_id, ());
                (cache, peer_id)
            },
            // routine
            |(mut cache, peer_id)| {
                cache.pop(&peer_id);
                (cache, peer_id) // drop outside of routine
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}
fn bench_pop_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("pop, full cache");
    group.bench_function("lru", |benches| {
        benches.iter_batched(
            // setup
            || {
                let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
                for _ in 0..CACHE_SIZE {
                    cache.put(PeerId::random(), ());
                }
                let peer_id = PeerId::random();
                cache.put(peer_id, ());
                (cache, peer_id)
            },
            // routine
            |(mut cache, peer_id)| {
                cache.pop(&peer_id);
                (cache, peer_id) // drop outside of routine
            },
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_contains_empty,
    bench_contains_full,
    bench_put_empty,
    bench_put_full,
    bench_pop_empty,
    bench_pop_full,
);
criterion_main!(benches);
