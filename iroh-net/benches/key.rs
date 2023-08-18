use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use crypto_box::aead::{Aead, AeadCore, OsRng};
use iroh_net::key::Keypair;
use rand::RngCore;

pub fn seal_to(c: &mut Criterion) {
    let mut group = c.benchmark_group("seal_to");
    for i in [64, 1024, 2048].iter() {
        let mut text = vec![0u8; *i];
        rand::thread_rng().fill_bytes(&mut text);

        group.bench_with_input(BenchmarkId::new("wrapper", i), i, |b, _| {
            let key = Keypair::generate();
            let target_key = Keypair::generate();

            b.iter(|| black_box(key.seal_to(&target_key.public(), &text)))
        });

        group.bench_with_input(BenchmarkId::new("raw", i), i, |b, _| {
            let mut rng = OsRng;
            let key = crypto_box::SecretKey::generate(&mut rng);
            let target_key = crypto_box::SecretKey::generate(&mut rng);
            b.iter(|| {
                let boxx = crypto_box::ChaChaBox::new(&target_key.public_key(), &key);
                let nonce = crypto_box::ChaChaBox::generate_nonce(&mut rng);
                let ciphertext = boxx.encrypt(&nonce, &text[..]).unwrap();
                let mut res = nonce.to_vec();
                res.extend(ciphertext);
                black_box(res)
            })
        });
    }
    group.finish();
}

pub fn open_from(c: &mut Criterion) {
    let mut group = c.benchmark_group("open_from");
    for i in [64, 1024, 2048].iter() {
        let mut text = vec![0u8; *i];
        rand::thread_rng().fill_bytes(&mut text);

        group.bench_with_input(BenchmarkId::new("wrapper", i), i, |b, _| {
            let key = Keypair::generate();
            let target_key = Keypair::generate();
            let cipher_text = key.seal_to(&target_key.public(), &text);

            b.iter(|| black_box(target_key.open_from(&key.public(), &cipher_text).unwrap()))
        });

        group.bench_with_input(BenchmarkId::new("raw", i), i, |b, _| {
            let mut rng = OsRng;
            let key = crypto_box::SecretKey::generate(&mut rng);
            let target_key = crypto_box::SecretKey::generate(&mut rng);
            let boxx = crypto_box::ChaChaBox::new(&key.public_key(), &target_key);
            let nonce = crypto_box::ChaChaBox::generate_nonce(&mut rng);
            let ciphertext = boxx.encrypt(&nonce, &text[..]).unwrap();
            let mut seal = nonce.to_vec();
            seal.extend(ciphertext);

            b.iter(|| {
                let (nonce, ciphertext) = seal.split_at(24);
                let nonce: [u8; 24] = nonce.try_into().unwrap();
                let res = boxx.decrypt(&nonce.into(), &ciphertext[..]).unwrap();
                black_box(res)
            })
        });
    }
    group.finish();
}

criterion_group!(benches, seal_to, open_from);
criterion_main!(benches);
