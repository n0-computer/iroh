//! Test the LRU cache implementation
//!
//! # Running the benchmarks
//!
//! Install `cargo-criterion`:
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

use caches::Cache;
use criterion::{criterion_group, criterion_main, Criterion};
use libp2p::PeerId;

// The size of the cache to make.  Taken from behaviour::peer_manager::DEFAULT_BAD_PEER_CAP.
const CACHE_SIZE: usize = 10 * 4096;

fn bench_contains_empty_cache(c: &mut Criterion) {
    let mut cache = caches::RawLRU::new(CACHE_SIZE).unwrap();
    let peer = PeerId::random();
    cache.put(peer, ());
    for _ in 0..16 {
        cache.put(PeerId::random(), ());
    }
    let missing = PeerId::random();
    assert!(!cache.contains(&missing));

    c.bench_function("caches: contains almost empty cache", |b| {
        b.iter(|| {
            cache.contains(&peer);
            cache.contains(&missing);
        })
    });
}

fn bench_lru_contains_empty_cache(c: &mut Criterion) {
    let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
    let peer = PeerId::random();
    cache.push(peer, ());
    for _ in 0..16 {
        cache.push(PeerId::random(), ());
    }
    let missing = PeerId::random();
    assert!(!cache.contains(&missing));

    c.bench_function("lru: contains almost empty cache", |b| {
        b.iter(|| {
            cache.contains(&peer);
            cache.contains(&missing);
        })
    });
}

fn bench_contains_full_cache(c: &mut Criterion) {
    let mut cache = caches::RawLRU::new(CACHE_SIZE).unwrap();
    let peer = PeerId::random();
    cache.put(peer, ());
    for _ in 0..CACHE_SIZE {
        cache.put(PeerId::random(), ());
    }
    let missing = PeerId::random();
    assert!(!cache.contains(&missing));

    c.bench_function("caches: contains full cache", |b| {
        b.iter(|| {
            cache.contains(&peer);
            cache.contains(&missing);
        })
    });
}

fn bench_lru_contains_full_cache(c: &mut Criterion) {
    let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
    let peer = PeerId::random();
    cache.push(peer, ());
    for _ in 0..CACHE_SIZE {
        cache.push(PeerId::random(), ());
    }
    let missing = PeerId::random();
    assert!(!cache.contains(&missing));

    c.bench_function("lru: contains full cache", |b| {
        b.iter(|| {
            cache.contains(&peer);
            cache.contains(&missing);
        })
    });
}

fn bench_put_empty_cache(c: &mut Criterion) {
    let mut cache = caches::RawLRU::new(CACHE_SIZE).unwrap();
    let peer_ids: [PeerId; 32] = std::array::from_fn(|_| PeerId::random());

    c.bench_function("caches: put almost empty cache", |b| {
        b.iter(|| {
            for i in 0..32 {
                cache.put(peer_ids[i], ());
            }
        })
    });
}

fn bench_lru_put_empty_cache(c: &mut Criterion) {
    let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
    let peer_ids: [PeerId; 32] = std::array::from_fn(|_| PeerId::random());

    c.bench_function("lru: put almost empty cache", |b| {
        b.iter(|| {
            for i in 0..32 {
                cache.push(peer_ids[i], ());
            }
        })
    });
}

fn bench_put_full_cache(c: &mut Criterion) {
    let mut cache = caches::RawLRU::new(CACHE_SIZE).unwrap();
    for _ in 0..CACHE_SIZE {
        cache.put(PeerId::random(), ());
    }
    let peer_ids: [PeerId; 32] = std::array::from_fn(|_| PeerId::random());

    c.bench_function("caches: put full cache", |b| {
        b.iter(|| {
            for i in 0..32 {
                cache.put(peer_ids[i], ());
            }
        })
    });
}

fn bench_lru_put_full_cache(c: &mut Criterion) {
    let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
    for _ in 0..CACHE_SIZE {
        cache.put(PeerId::random(), ());
    }
    let peer_ids: [PeerId; 32] = std::array::from_fn(|_| PeerId::random());

    c.bench_function("lru: put full cache", |b| {
        b.iter(|| {
            for i in 0..32 {
                cache.push(peer_ids[i], ());
            }
        })
    });
}

fn bench_remove_empty_cache(c: &mut Criterion) {
    let mut cache = caches::RawLRU::new(CACHE_SIZE).unwrap();
    let peer_ids: [PeerId; 32] = std::array::from_fn(|_| PeerId::random());
    for peer_id in peer_ids {
        cache.put(peer_id, ());
    }

    c.bench_function("caches: remove almost empty cache", |b| {
        b.iter(|| {
            for i in 0..16 {
                cache.remove(&peer_ids[i]);
            }
        })
    });
}

fn bench_lru_remove_empty_cache(c: &mut Criterion) {
    let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
    let peer_ids: [PeerId; 32] = std::array::from_fn(|_| PeerId::random());
    for peer_id in peer_ids {
        cache.push(peer_id, ());
    }

    c.bench_function("lru: remove almost empty cache", |b| {
        b.iter(|| {
            for i in 0..16 {
                cache.pop(&peer_ids[i]);
            }
        })
    });
}

fn bench_remove_full_cache(c: &mut Criterion) {
    let mut cache = caches::RawLRU::new(CACHE_SIZE).unwrap();
    for _ in 0..CACHE_SIZE {
        cache.put(PeerId::random(), ());
    }
    let peer_ids: [PeerId; 16] = std::array::from_fn(|_| PeerId::random());
    for peer_id in peer_ids {
        cache.put(peer_id, ());
    }

    c.bench_function("caches: remove full cache", |b| {
        b.iter(|| {
            for i in 0..16 {
                cache.remove(&peer_ids[i]);
            }
        })
    });
}

fn bench_lru_remove_full_cache(c: &mut Criterion) {
    let mut cache = lru::LruCache::new(CACHE_SIZE.try_into().unwrap());
    for _ in 0..CACHE_SIZE {
        cache.push(PeerId::random(), ());
    }
    let peer_ids: [PeerId; 16] = std::array::from_fn(|_| PeerId::random());
    for peer_id in peer_ids {
        cache.push(peer_id, ());
    }

    c.bench_function("lru: remove full cache", |b| {
        b.iter(|| {
            for i in 0..16 {
                cache.pop(&peer_ids[i]);
            }
        })
    });
}

criterion_group!(
    benches,
    bench_contains_empty_cache,
    bench_contains_full_cache,
    bench_put_empty_cache,
    bench_put_full_cache,
    bench_remove_empty_cache,
    bench_remove_full_cache,
    bench_lru_contains_empty_cache,
    bench_lru_contains_full_cache,
    bench_lru_put_empty_cache,
    bench_lru_put_full_cache,
    bench_lru_remove_empty_cache,
    bench_lru_remove_full_cache,
);
criterion_main!(benches);
