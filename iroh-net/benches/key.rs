use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use crypto_box::aead::{AeadCore, AeadInPlace, OsRng};
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

            b.iter(|| {
                let shared = key.shared(&target_key.public());
                let mut res = text.clone();
                shared.seal(&mut res);
                black_box(res)
            })
        });

        group.bench_with_input(BenchmarkId::new("raw", i), i, |b, _| {
            let mut rng = OsRng;
            let key = crypto_box::SecretKey::generate(&mut rng);
            let target_key = crypto_box::SecretKey::generate(&mut rng);
            b.iter(|| {
                let boxx = crypto_box::ChaChaBox::new(&target_key.public_key(), &key);
                let nonce = crypto_box::ChaChaBox::generate_nonce(&mut rng);
                let mut ciphertext = text.clone();
                boxx.encrypt_in_place(&nonce, &[], &mut ciphertext).unwrap();
                ciphertext.extend_from_slice(&nonce);
                black_box(ciphertext)
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
            let shared = key.shared(&target_key.public());
            let mut cipher_text = text.clone();
            shared.seal(&mut cipher_text);

            b.iter(|| {
                let shared = target_key.shared(&key.public());
                let mut res = cipher_text.clone();
                shared.open(&mut res).unwrap();
                black_box(res)
            })
        });

        group.bench_with_input(BenchmarkId::new("raw", i), i, |b, _| {
            let mut rng = OsRng;
            let key = crypto_box::SecretKey::generate(&mut rng);
            let target_key = crypto_box::SecretKey::generate(&mut rng);
            let boxx = crypto_box::ChaChaBox::new(&key.public_key(), &target_key);
            let nonce = crypto_box::ChaChaBox::generate_nonce(&mut rng);
            let mut ciphertext = text.clone();
            boxx.encrypt_in_place(&nonce, &[], &mut ciphertext).unwrap();
            ciphertext.extend_from_slice(&nonce);

            b.iter(|| {
                let mut ciphertext = ciphertext.clone();
                let offset = ciphertext.len() - 24;
                let nonce: [u8; 24] = ciphertext[offset..].try_into().unwrap();
                ciphertext.truncate(offset);
                let boxx = crypto_box::ChaChaBox::new(&target_key.public_key(), &key);
                boxx.decrypt_in_place(&nonce.into(), &[], &mut ciphertext)
                    .unwrap();
                black_box(ciphertext)
            })
        });
    }
    group.finish();
}

criterion_group!(benches, seal_to, open_from);
criterion_main!(benches);
