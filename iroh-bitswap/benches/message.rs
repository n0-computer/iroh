use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use iroh_bitswap::{
    create_test_block_v1 as create_test_block, BitswapMessage, Priority, ProtocolId,
};

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        let message = BitswapMessage::new();
        let packet = message.to_bytes(ProtocolId::Bitswap120);

        c.bench_function("BitswapMessage::from_bytes - empty", |b| {
            b.iter(|| {
                let res =
                    BitswapMessage::from_bytes(ProtocolId::Bitswap120, packet.clone()).unwrap();
                black_box(res);
            })
        });

        c.bench_function("BitswapMessage::to_bytes - empty", |b| {
            b.iter(|| {
                let res = message.to_bytes(ProtocolId::Bitswap120);
                black_box(res);
            })
        });
    }

    {
        let mut message = BitswapMessage::new();
        let block0 = create_test_block(Bytes::from(vec![0; 1024 * 1024]));
        let block1 = create_test_block(Bytes::from(vec![1; 1024 * 1024]));

        message
            .wantlist_mut()
            .want_block(block0.cid(), Priority::default());

        let packet = message.to_bytes(ProtocolId::Bitswap120);

        c.bench_function("BitswapMessage::from_bytes - tiny - want", |b| {
            b.iter_batched(
                || packet.clone(),
                |packet| {
                    let res = BitswapMessage::from_bytes(ProtocolId::Bitswap120, packet).unwrap();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });

        c.bench_function("BitswapMessage::into_bytes - tiny - want", |b| {
            b.iter_batched(
                || message.clone(),
                |message| {
                    let res = message.into_bytes(ProtocolId::Bitswap120);
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });

        let mut message = BitswapMessage::new();
        message.add_block(block1);
        let packet = message.to_bytes(ProtocolId::Bitswap120);

        c.bench_function("BitswapMessage::from_bytes - tiny - get", |b| {
            b.iter_batched(
                || packet.clone(),
                |packet| {
                    let res = BitswapMessage::from_bytes(ProtocolId::Bitswap120, packet).unwrap();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });

        c.bench_function("BitswapMessage::into_bytes - tiny - get", |b| {
            b.iter_batched(
                || message.clone(),
                |message| {
                    let res = message.into_bytes(ProtocolId::Bitswap120);
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });
    }

    {
        let mut message = BitswapMessage::new();
        for i in 0..10 {
            let block0 = create_test_block(Bytes::from(vec![i; 1024 * 1024]));
            let block1 = create_test_block(Bytes::from(vec![i + 1; 1024 * 1024]));

            message
                .wantlist_mut()
                .want_block(block0.cid(), Priority::default());
            message.add_block(block1);
        }

        let packet = message.to_bytes(ProtocolId::Bitswap120);

        c.bench_function("BitswapMessage::from_bytes - small", |b| {
            b.iter(|| {
                let res =
                    BitswapMessage::from_bytes(ProtocolId::Bitswap120, packet.clone()).unwrap();
                black_box(res);
            })
        });

        c.bench_function("BitswapMessage::to_bytes - small", |b| {
            b.iter(|| {
                let res = message.to_bytes(ProtocolId::Bitswap120);
                black_box(res);
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
