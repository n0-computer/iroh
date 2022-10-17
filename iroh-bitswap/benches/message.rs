use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use iroh_bitswap::{
    create_block_v1 as create_test_block,
    message::{BitswapMessage, Priority, WantType},
};

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        let message = BitswapMessage::new(true);
        let packet = message.encode_as_proto_v1();

        c.bench_function("BitswapMessage::from_bytes - empty", |b| {
            b.iter(|| {
                let res = BitswapMessage::try_from(packet.clone()).unwrap();
                black_box(res);
            })
        });

        c.bench_function("BitswapMessage::to_bytes - empty", |b| {
            b.iter(|| {
                let res = message.encode_as_proto_v1();
                black_box(res);
            })
        });
    }

    {
        let mut message = BitswapMessage::new(true);
        let block0 = create_test_block(Bytes::from(vec![0; 1024 * 1024]));
        let block1 = create_test_block(Bytes::from(vec![1; 1024 * 1024]));

        message.add_entry(*block0.cid(), Priority::default(), WantType::Block, true);

        let packet = message.encode_as_proto_v1();

        c.bench_function("BitswapMessage::from_bytes - tiny - want", |b| {
            b.iter_batched(
                || packet.clone(),
                |packet| {
                    let res = BitswapMessage::try_from(packet).unwrap();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });

        c.bench_function("BitswapMessage::into_bytes - tiny - want", |b| {
            b.iter_batched(
                || message.clone(),
                |message| {
                    let res = message.encode_as_proto_v1();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });

        let mut message = BitswapMessage::new(true);
        message.add_block(block1);
        let packet = message.encode_as_proto_v1();

        c.bench_function("BitswapMessage::from_bytes - tiny - get", |b| {
            b.iter_batched(
                || packet.clone(),
                |packet| {
                    let res = BitswapMessage::try_from(packet).unwrap();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });

        c.bench_function("BitswapMessage::into_bytes - tiny - get", |b| {
            b.iter_batched(
                || message.clone(),
                |message| {
                    let res = message.encode_as_proto_v1();
                    black_box(res);
                },
                BatchSize::SmallInput,
            )
        });
    }

    {
        let mut message = BitswapMessage::new(true);
        for i in 0..10 {
            let block0 = create_test_block(Bytes::from(vec![i; 1024 * 1024]));
            let block1 = create_test_block(Bytes::from(vec![i + 1; 1024 * 1024]));

            message.add_entry(*block0.cid(), Priority::default(), WantType::Block, true);
            message.add_block(block1.clone());
        }

        let packet = message.encode_as_proto_v1();

        c.bench_function("BitswapMessage::from_bytes - small", |b| {
            b.iter(|| {
                let res = BitswapMessage::try_from(packet.clone()).unwrap();
                black_box(res);
            })
        });

        c.bench_function("BitswapMessage::to_bytes - small", |b| {
            b.iter(|| {
                let res = message.encode_as_proto_v1();
                black_box(res);
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
