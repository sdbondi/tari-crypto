// Copyright 2022. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
#![allow(missing_docs)]
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group};
use rand::{Rng, rng};
use tari_crypto::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
};

fn generate_secret_key(c: &mut Criterion) {
    c.bench_function("Generate secret key", |b| {
        let mut rng = rng();
        b.iter(|| {
            let _key = RistrettoSecretKey::random(&mut rng);
        });
    });
}

fn native_keypair(c: &mut Criterion) {
    c.bench_function("Generate key pair", |b| {
        let mut rng = rng();
        b.iter(|| RistrettoPublicKey::random_keypair(&mut rng));
    });
}

struct SigningData {
    k: RistrettoSecretKey,
    p: RistrettoPublicKey,
    m: [u8; 32],
}

fn gen_keypair() -> SigningData {
    let mut rng = rng();
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    let (k, p) = RistrettoPublicKey::random_keypair(&mut rng);
    SigningData { k, p, m }
}

fn sign_message(c: &mut Criterion) {
    c.bench_function("Create RistrettoSchnorr", move |b| {
        b.iter_batched(
            gen_keypair,
            |d| {
                let _sig = RistrettoSchnorr::sign(&d.k, d.m, &mut rng()).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    //    assert!(sig.verify(&p, &msg_key));
}

fn verify_message(c: &mut Criterion) {
    c.bench_function("Verify RistrettoSchnorr", move |b| {
        b.iter_batched(
            || {
                let d = gen_keypair();
                let s = RistrettoSchnorr::sign(&d.k, d.m, &mut rng()).unwrap();
                (d, s)
            },
            |(d, s)| assert!(s.verify(&d.p, d.m)),
            BatchSize::SmallInput,
        );
    });
}

/// Signs `n` distinct messages under `n` fresh keys.
fn signed_batch(n: usize) -> Vec<(RistrettoSchnorr, RistrettoPublicKey, [u8; 32])> {
    let mut rng = rng();
    (0..n)
        .map(|_| {
            let d = gen_keypair();
            let s = RistrettoSchnorr::sign(&d.k, d.m, &mut rng).unwrap();
            (s, d.p, d.m)
        })
        .collect()
}

/// Per-signature verification against batch verification over the same set.
///
/// The batch is signed once, outside the measurement, and every iteration verifies that same fixed input. Signing
/// fresh signatures per iteration would swamp a difference of tens of microseconds in setup noise. Verification is
/// stateless, so reuse changes nothing but the variance.
///
/// `n = 1` and `n = 2` matter as much as the large sizes: most Ootle transactions carry a single seal plus a
/// single authorization, so the batch must not lose there.
fn verify_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch verify RistrettoSchnorr");
    for n in [1usize, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        group.throughput(Throughput::Elements(n as u64));

        let batch = signed_batch(n);
        let items: Vec<_> = batch.iter().map(|(s, p, m)| (s, p, m.as_slice())).collect();

        group.bench_with_input(BenchmarkId::new("individually", n), &n, |b, _| {
            b.iter(|| {
                for (s, p, m) in &batch {
                    assert!(s.verify(p, m));
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("deterministic weights", n), &n, |b, _| {
            b.iter(|| assert!(RistrettoSchnorr::verify_batch(&items)));
        });

        group.bench_with_input(BenchmarkId::new("random weights", n), &n, |b, _| {
            b.iter(|| assert!(RistrettoSchnorr::verify_batch_with_rng(&items, &mut rng())));
        });
    }
    group.finish();
}

criterion_group!(
name = signatures;
config = Criterion::default().warm_up_time(Duration::from_millis(500));
targets = generate_secret_key, native_keypair, sign_message, verify_message, verify_batch
);
