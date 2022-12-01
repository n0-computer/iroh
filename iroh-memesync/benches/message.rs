use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use iroh_memesync::{create_test_block, Message as MemesyncMessage, Priority};

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        let message = MemesyncMessage::new();
        let packet = message.to_bytes();

        c.bench_function("MemesyncMessage::from_bytes - empty", |b| {
            b.iter(|| {
                let res = MemesyncMessage::from_bytes(packet.clone()).unwrap();
                black_box(res);
            })
        });

        c.bench_function("MemesyncMessage::to_bytes - empty", |b| {
            b.iter(|| {
                let res = message.to_bytes();
                black_box(res);
            })
        });
    }

    {
        let mut message = MemesyncMessage::new();
        let block0 = create_test_block(Bytes::from(vec![0; 1024 * 1024]));
        let block1 = create_test_block(Bytes::from(vec![1; 1024 * 1024]));

        message
            .wantlist_mut()
            .want_block(block0.cid(), Priority::default());

        let packet = message.to_bytes();

        c.bench_function("MemesyncMessage::from_bytes - tiny - want", |b| {
            b.iter_batched(
                || packet.clone(),
                |packet| {
                    let res = MemesyncMessage::from_bytes(packet).unwrap();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });

        c.bench_function("MemesyncMessage::into_bytes - tiny - want", |b| {
            b.iter_batched(
                || message.clone(),
                |message| {
                    let res = message.into_bytes();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });

        let mut message = MemesyncMessage::new();
        message.add_block(block1);
        let packet = message.to_bytes();

        c.bench_function("MemesyncMessage::from_bytes - tiny - get", |b| {
            b.iter_batched(
                || packet.clone(),
                |packet| {
                    let res = MemesyncMessage::from_bytes(packet).unwrap();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });

        c.bench_function("MemesyncMessage::into_bytes - tiny - get", |b| {
            b.iter_batched(
                || message.clone(),
                |message| {
                    let res = message.into_bytes();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });
    }

    {
        let mut message = MemesyncMessage::new();
        for i in 0..10 {
            let block0 = create_test_block(Bytes::from(vec![i; 1024 * 1024]));
            let block1 = create_test_block(Bytes::from(vec![i + 1; 1024 * 1024]));

            message
                .wantlist_mut()
                .want_block(block0.cid(), Priority::default());
            message.add_block(block1);
        }

        let packet = message.to_bytes();

        c.bench_function("MemesyncMessage::from_bytes - small", |b| {
            b.iter(|| {
                let res = MemesyncMessage::from_bytes(packet.clone()).unwrap();
                black_box(res);
            })
        });

        c.bench_function("MemesyncMessage::to_bytes - small", |b| {
            b.iter(|| {
                let res = message.to_bytes();
                black_box(res);
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
