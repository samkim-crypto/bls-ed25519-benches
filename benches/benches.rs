use bls_signatures::{
    aggregate, hash, verify, PrivateKey as BLSPrivateKey, Signature as BLSSignature,
};
use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Keypair as Ed25519Keypair, Signature as Ed25519Signature, Signer};
use rand::Rng;

macro_rules! bls_verify {
    ($name:ident, $num:expr) => {
        fn $name(c: &mut Criterion) {
            let private_keys: Vec<_> = (0..$num).map(|_| BLSPrivateKey::generate()).collect();
            let public_keys = private_keys
                .iter()
                .map(|pk| pk.public_key())
                .collect::<Vec<_>>();

            let rng = &mut rand::thread_rng();
            let messages: Vec<Vec<u8>> = (0..$num)
                .map(|_| (0..$num).map(|_| rng.gen()).collect())
                .collect();

            // sign messages
            let sigs = messages
                .iter()
                .zip(&private_keys)
                .map(|(message, pk)| pk.sign(message))
                .collect::<Vec<BLSSignature>>();

            let aggregated_signature = aggregate(&sigs).unwrap();

            c.bench_function(stringify!($name), |b| {
                b.iter(|| {
                    let hashes = messages
                        .iter()
                        .map(|message| hash(message))
                        .collect::<Vec<_>>();
                    verify(&aggregated_signature, &hashes, &public_keys);
                })
            });
        }
    };
}

bls_verify!(bls_verify_10, 10);
bls_verify!(bls_verify_100, 100);
bls_verify!(bls_verify_1000, 1000);
bls_verify!(bls_verify_2000, 2000);

macro_rules! ed25519_verify {
    ($name:ident, $num:expr) => {
        fn $name(c: &mut Criterion) {
            let mut rng = rand::thread_rng();
            let keypair: Ed25519Keypair = Ed25519Keypair::generate(&mut rng);

            let messages: Vec<Vec<u8>> = (0..$num)
                .map(|_| (0..$num).map(|_| rng.gen()).collect())
                .collect();

            let sigs = messages
                .iter()
                .map(|message| keypair.sign(&message))
                .collect::<Vec<Ed25519Signature>>();

            c.bench_function(stringify!($name), |b| {
                b.iter(|| {
                    for (message, signature) in messages.iter().zip(sigs.iter()) {
                        keypair.verify(&message, &signature).unwrap();
                    }
                })
            });
        }
    };
}

ed25519_verify!(ed25519_verify_10, 10);
ed25519_verify!(ed25519_verify_100, 100);
ed25519_verify!(ed25519_verify_1000, 1000);
ed25519_verify!(ed25519_verify_2000, 2000);

criterion_group!(
    benches,
    bls_verify_10,
    bls_verify_100,
    bls_verify_1000,
    bls_verify_2000,
    ed25519_verify_10,
    ed25519_verify_100,
    ed25519_verify_1000,
    ed25519_verify_2000,
);
criterion_main!(benches);
