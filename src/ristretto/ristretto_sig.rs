// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    signatures::{CompressedSchnorrSignature, SchnorrSigChallenge, SchnorrSignature},
};

/// # A Schnorr signature implementation on Ristretto
///
/// Find out more about [Schnorr signatures](https://tlu.tarilabs.com/cryptography/digital_signatures/introduction.html).
///
/// `RistrettoSchnorr` utilises the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek1)
/// implementation of `ristretto255` to provide Schnorr signature functionality.
///
/// In short, a Schnorr sig is made up of the pair _(R, s)_, where _R_ is a public key (of a secret nonce) and _s_ is
/// the signature.
///
/// ## Creating signatures
///
/// You can create a `RisrettoSchnorr` from its component parts:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::signatures::SchnorrSignature;
/// # use tari_utilities::ByteArray;
/// # use tari_utilities::hex::Hex;
///
/// let public_r = RistrettoPublicKey::from_hex(
///     "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
/// )
/// .unwrap();
/// let s = RistrettoSecretKey::from_hex(
///     "f62fccf7734099d32937f7f767757abcb6eca70f43b3a7fb6500b2cb9ea12b02",
/// )
/// .unwrap();
/// let sig = RistrettoSchnorr::new(public_r, s);
/// ```
///
/// or you can create a signature by signing a message:
///
/// ```rust
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::signatures::SchnorrSignature;
/// # use digest::Digest;
/// # use rand::{Rng, rng};
///
/// fn get_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
///     let mut rng = rand::rng();
///     let k = RistrettoSecretKey::random(&mut rng);
///     let pk = RistrettoPublicKey::from_secret_key(&k);
///     (k, pk)
/// }
///
/// #[allow(non_snake_case)]
/// let (k, P) = get_keypair();
/// let msg = "Small Gods";
/// let mut rng = rng();
/// let sig = RistrettoSchnorr::sign(&k, &msg, &mut rng);
/// ```
///
/// # Verifying signatures
///
/// Given a signature, (R,s) and a Challenge, e, you can verify that the signature is valid by calling the `verify`
/// method:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::signatures::SchnorrSignature;
/// # use tari_utilities::hex::*;
/// # use tari_utilities::ByteArray;
/// # use digest::Digest;
/// # use rand::{Rng, rng};
///
/// let msg = "Maskerade";
/// let k = RistrettoSecretKey::from_hex(
///     "bd0b253a619310340a4fa2de54cdd212eac7d088ee1dc47e305c3f6cbd020908",
/// )
/// .unwrap();
/// # #[allow(non_snake_case)]
/// let P = RistrettoPublicKey::from_secret_key(&k);
/// let mut rng = rng();
/// let sig: SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey> =
///     SchnorrSignature::sign(&k, msg, &mut rng).unwrap();
/// assert!(sig.verify(&P, msg));
/// ```
pub type RistrettoSchnorr = SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>;
/// # A compressed Schnorr signature implementation on Ristretto
pub type CompressedRistrettoSchnorr =
    CompressedSchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>;

/// # A Schnorr signature implementation on Ristretto with a custom domain separation tag
///
/// Usage is identical to [`RistrettoSchnorr`], except that you are able to specify the domain separation tag to use
/// when computing challenges for the signature.
///
/// ## Example
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::hash_domain;
/// # use tari_crypto::signatures::SchnorrSignature;
/// # use tari_utilities::hex::*;
/// # use rand::{Rng, rng};
/// # use tari_utilities::ByteArray;
/// # use digest::Digest;
///
/// hash_domain!(MyCustomDomain, "com.example.custom");
///
/// let msg = "Maskerade";
/// let k = RistrettoSecretKey::from_hex(
///     "bd0b253a619310340a4fa2de54cdd212eac7d088ee1dc47e305c3f6cbd020908",
/// )
/// .unwrap();
/// # #[allow(non_snake_case)]
/// let P = RistrettoPublicKey::from_secret_key(&k);
/// let mut rng = rng();
/// let sig: SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, MyCustomDomain> =
///     SchnorrSignature::sign(&k, msg, &mut rng).unwrap();
/// assert!(sig.verify(&P, msg));
/// ```
pub type RistrettoSchnorrWithDomain<H> = SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, H>;

#[cfg(test)]
mod test {
    use blake2::Blake2b;
    use digest::{Digest, consts::U64};
    use tari_utilities::{
        ByteArray,
        hex::{Hex, to_hex},
    };

    use crate::{
        hash_domain,
        keys::{PublicKey, SecretKey},
        ristretto::{
            RistrettoPublicKey,
            RistrettoSchnorr,
            RistrettoSecretKey,
            ristretto_sig::RistrettoSchnorrWithDomain,
        },
        signatures::{SchnorrSigChallenge, SchnorrSignature},
    };

    #[test]
    fn default() {
        let sig = RistrettoSchnorr::default();
        assert_eq!(sig.get_signature(), &RistrettoSecretKey::default());
        assert_eq!(sig.get_public_nonce(), &RistrettoPublicKey::default());
    }

    /// Create a signature, and then verify it. Also checks that some invalid signatures fail to verify
    #[test]
    #[allow(non_snake_case)]
    fn raw_sign_and_verify_challenge() {
        let mut rng = rand::rng();
        let (k, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r, R) = RistrettoPublicKey::random_keypair(&mut rng);
        // Use sign raw, and bind the nonce and public key manually
        let e = Blake2b::<U64>::new()
            .chain_update(P.as_bytes())
            .chain_update(R.as_bytes())
            .chain_update(b"Small Gods")
            .finalize();
        let e_key = RistrettoSecretKey::from_uniform_bytes(&e).unwrap();
        let s = &r + &e_key * &k;
        let sig = RistrettoSchnorr::sign_raw_uniform(&k, r, &e).unwrap();
        let R_calc = sig.get_public_nonce();
        assert_eq!(R, *R_calc);
        assert_eq!(sig.get_signature(), &s);
        assert!(sig.verify_raw_uniform(&P, &e));
        // Doesn't work for invalid credentials
        assert!(!sig.verify_raw_uniform(&R, &e));
        // Doesn't work for different challenge
        let wrong_challenge = Blake2b::<U64>::digest(b"Guards! Guards!");
        assert!(!sig.verify_raw_uniform(&P, &wrong_challenge));
    }

    /// This test checks that the linearity of Schnorr signatures hold, i.e. that s = s1 + s2 is validated by R1 + R2
    /// and P1 + P2. We do this by hand here rather than using the APIs to guard against regressions
    #[test]
    #[allow(non_snake_case)]
    fn test_signature_addition() {
        let mut rng = rand::rng();
        // Alice and Bob generate some keys and nonces
        let (k1, P1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r1, R1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (k2, P2) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r2, R2) = RistrettoPublicKey::random_keypair(&mut rng);
        // Each of them creates the Challenge = H(R1 || R2 || P1 || P2 || m)
        let e = Blake2b::<U64>::new()
            .chain_update(R1.as_bytes())
            .chain_update(R2.as_bytes())
            .chain_update(P1.as_bytes())
            .chain_update(P2.as_bytes())
            .chain_update(b"Moving Pictures")
            .finalize();
        // Calculate Alice's signature
        let s1 = RistrettoSchnorr::sign_raw_uniform(&k1, r1, &e).unwrap();
        // Calculate Bob's signature
        let s2 = RistrettoSchnorr::sign_raw_uniform(&k2, r2, &e).unwrap();
        // Now add the two signatures together
        let s_agg = &s1 + &s2;
        // Check that the multi-sig verifies
        assert!(s_agg.verify_raw_uniform(&(P1 + P2), &e));
    }

    #[test]
    #[allow(non_snake_case)]
    fn domain_separated_challenge() {
        let P =
            RistrettoPublicKey::from_hex("74896a30c89186b8194e25f8c1382f8d3081c5a182fb8f8a6d34f27fbefbfc70").unwrap();
        let R =
            RistrettoPublicKey::from_hex("fa14cb581ce5717248444721242e6b195a482d503a853dea4acb513074d8d803").unwrap();
        let msg = "Moving Pictures";
        let hash = SchnorrSignature::<_, _, SchnorrSigChallenge>::construct_domain_separated_challenge::<_, Blake2b<U64>>(
            &R, &P, msg,
        );
        let naiive = Blake2b::<U64>::new()
            .chain_update(R.as_bytes())
            .chain_update(P.as_bytes())
            .chain_update(msg)
            .finalize()
            .to_vec();
        assert_ne!(hash.as_ref(), naiive.as_bytes());
        assert_eq!(
            to_hex(hash.as_ref()),
            "2db0656c9dd1482bf61d32f157726b05a88d567c31107bed9a5c60a02119518af35929f360726bffd846439ab12e7c9f4983cf5fab5ea735422e05e0f560ddfd"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn custom_hash_domain() {
        hash_domain!(TestDomain, "test.signature.com");
        let mut rng = rand::rng();
        let (k, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r, _) = RistrettoPublicKey::random_keypair(&mut rng);
        let msg = "Moving Pictures";
        // Using default domain
        // NEVER re-use nonces in practice. This is done here explicitly to indicate that the domain separation
        // prevents accidental signature duplication.
        let sig1 = RistrettoSchnorr::sign_with_nonce_and_message(&k, r.clone(), msg).unwrap();
        // Using custom domain
        let sig2 = RistrettoSchnorrWithDomain::<TestDomain>::sign_with_nonce_and_message(&k, r, msg).unwrap();
        // The type system won't even let this compile :)
        // assert_ne!(sig1, sig2);
        // Prove that the nonces were reused. Again, NEVER do this
        assert_eq!(sig1.get_public_nonce(), sig2.get_public_nonce());
        assert!(sig1.verify(&P, msg));
        assert!(sig2.verify(&P, msg));
        // But the signatures are different, for the same message, secret and nonce.
        assert_ne!(sig1.get_signature(), sig2.get_signature());
    }

    #[test]
    #[allow(non_snake_case)]
    fn sign_and_verify_message() {
        let mut rng = rand::rng();
        let (k, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let sig = RistrettoSchnorr::sign(&k, "Queues are things that happen to other people", &mut rng).unwrap();
        assert!(sig.verify(&P, "Queues are things that happen to other people"));
        assert!(!sig.verify(&P, "Qs are things that happen to other people"));
        assert!(!sig.verify(&(&P + &P), "Queues are things that happen to other people"));
    }

    /// Vartime batch verification.
    mod batch {
        use alloc::{vec, vec::Vec};

        use rand::rng;

        use super::*;

        struct Signed {
            public_key: RistrettoPublicKey,
            signature: RistrettoSchnorr,
            message: Vec<u8>,
        }

        /// Signs `n` distinct messages under `n` fresh keys.
        fn sign_n(n: usize) -> Vec<Signed> {
            let mut rng = rng();
            (0..n)
                .map(|i| {
                    let (k, public_key) = RistrettoPublicKey::random_keypair(&mut rng);
                    let message = format!("message {i}").into_bytes();
                    let signature = RistrettoSchnorr::sign(&k, &message, &mut rng).unwrap();
                    Signed {
                        public_key,
                        signature,
                        message,
                    }
                })
                .collect()
        }

        fn items(signed: &[Signed]) -> Vec<(&RistrettoSchnorr, &RistrettoPublicKey, &[u8])> {
            signed
                .iter()
                .map(|s| (&s.signature, &s.public_key, s.message.as_slice()))
                .collect()
        }

        /// Asserts that both batch verifiers agree with the per-signature verifier on this set, and reports which
        /// verdict they reached.
        fn assert_agrees(signed: &[Signed], case: &str) -> bool {
            let expected = signed.iter().all(|s| s.signature.verify(&s.public_key, &s.message));
            let items = items(signed);
            assert_eq!(RistrettoSchnorr::verify_batch(&items), expected, "{case}");
            assert_eq!(
                RistrettoSchnorr::verify_batch_with_rng(&items, &mut rng()),
                expected,
                "{case}"
            );
            expected
        }

        /// Asserts that the set is accepted, by the batch verifiers and by the per-signature verifier alike.
        fn assert_accepts(signed: &[Signed], case: &str) {
            assert!(assert_agrees(signed, case), "{case}");
        }

        /// Asserts that the set is rejected, and that the per-signature verifier rejects it too, so that a passing
        /// negative test can never be one that both verifiers happen to accept.
        fn assert_rejects(signed: &[Signed], case: &str) {
            assert!(!assert_agrees(signed, case), "{case}");
        }

        #[test]
        fn empty_batch_is_vacuously_valid() {
            let items: Vec<(&RistrettoSchnorr, &RistrettoPublicKey, &[u8])> = vec![];
            assert!(RistrettoSchnorr::verify_batch(&items));
            assert!(RistrettoSchnorr::verify_batch_with_rng(&items, &mut rng()));
        }

        /// The batch verdict must match the per-signature verdict, with a foreign signature planted at every
        /// position for small batches and at the ends and middle for large ones.
        #[test]
        fn agrees_with_per_signature_verify() {
            for n in [1usize, 2, 3, 4, 8, 33] {
                let mut signed = sign_n(n);
                assert_accepts(&signed, &format!("n = {n}, untouched"));

                let positions: Vec<usize> = if n <= 8 {
                    (0..n).collect()
                } else {
                    vec![0, n / 2, n - 1]
                };
                let foreign = sign_n(1).pop().unwrap();
                for position in positions {
                    let original = core::mem::replace(&mut signed[position].signature, foreign.signature.clone());
                    assert_rejects(&signed, &format!("n = {n}, foreign signature at {position}"));
                    signed[position].signature = original;
                }

                assert_accepts(&signed, &format!("n = {n}, restored"));
            }
        }

        /// Two signatures whose defects are `+δG` and `−δG` cancel exactly when summed unweighted. This is the
        /// attack the weights exist to stop.
        #[test]
        fn rejects_cancelling_errors() {
            let mut rng = rng();
            let mut signed = sign_n(2);
            let delta = RistrettoSecretKey::random(&mut rng);

            signed[0].signature = RistrettoSchnorr::new(
                signed[0].signature.get_public_nonce().clone(),
                signed[0].signature.get_signature() + &delta,
            );
            signed[1].signature = RistrettoSchnorr::new(
                signed[1].signature.get_public_nonce().clone(),
                signed[1].signature.get_signature() - &delta,
            );

            // Neither signature verifies on its own, and the unweighted sum of their defects is zero
            assert!(!signed[0].signature.verify(&signed[0].public_key, &signed[0].message));
            assert!(!signed[1].signature.verify(&signed[1].public_key, &signed[1].message));
            assert_rejects(&signed, "cancelling +δG / -δG pair");
        }

        /// Swapping any component between two terms must be caught.
        #[test]
        fn rejects_permuted_components() {
            // Public keys
            let mut signed = sign_n(2);
            let (first, rest) = signed.split_at_mut(1);
            core::mem::swap(&mut first[0].public_key, &mut rest[0].public_key);
            assert_rejects(&signed, "public keys swapped");

            // Public nonces
            let mut signed = sign_n(2);
            let swapped = (
                RistrettoSchnorr::new(
                    signed[1].signature.get_public_nonce().clone(),
                    signed[0].signature.get_signature().clone(),
                ),
                RistrettoSchnorr::new(
                    signed[0].signature.get_public_nonce().clone(),
                    signed[1].signature.get_signature().clone(),
                ),
            );
            signed[0].signature = swapped.0;
            signed[1].signature = swapped.1;
            assert_rejects(&signed, "public nonces swapped");

            // Signature scalars
            let mut signed = sign_n(2);
            let swapped = (
                RistrettoSchnorr::new(
                    signed[0].signature.get_public_nonce().clone(),
                    signed[1].signature.get_signature().clone(),
                ),
                RistrettoSchnorr::new(
                    signed[1].signature.get_public_nonce().clone(),
                    signed[0].signature.get_signature().clone(),
                ),
            );
            signed[0].signature = swapped.0;
            signed[1].signature = swapped.1;
            assert_rejects(&signed, "signature scalars swapped");
        }

        /// Under `P = 0` the batch equation degenerates to `s·G == R`, which anyone can satisfy, so the identity key
        /// has to be rejected up front.
        #[test]
        fn rejects_identity_public_key() {
            let mut rng = rng();
            let zero = RistrettoSecretKey::default();
            let identity = RistrettoPublicKey::from_secret_key(&zero);
            assert_eq!(identity, RistrettoPublicKey::default());

            let message = b"A secret message".to_vec();
            let signature = RistrettoSchnorr::sign(&zero, &message, &mut rng).unwrap();
            let forged = Signed {
                public_key: identity,
                signature,
                message,
            };

            // Alone
            assert_rejects(core::slice::from_ref(&forged), "identity public key alone");

            // And next to a valid signature, at either end
            let mut signed = sign_n(1);
            signed.push(forged);
            assert_rejects(&signed, "identity public key last");
            signed.swap(0, 1);
            assert_rejects(&signed, "identity public key first");
        }

        /// Ootle batches a seal, which signs a different message, together with the transaction authorizations.
        #[test]
        fn mixed_messages_in_one_batch() {
            let mut rng = rng();
            let (k, public_key) = RistrettoPublicKey::random_keypair(&mut rng);
            let seal = b"seal".to_vec();
            let authorization = b"authorization".to_vec();

            let signed = vec![
                Signed {
                    public_key: public_key.clone(),
                    signature: RistrettoSchnorr::sign(&k, &seal, &mut rng).unwrap(),
                    message: seal.clone(),
                },
                Signed {
                    public_key: public_key.clone(),
                    signature: RistrettoSchnorr::sign(&k, &authorization, &mut rng).unwrap(),
                    message: authorization,
                },
            ];
            assert_accepts(&signed, "seal and authorization");

            // The same signature under the wrong message of the pair must not slip through
            let swapped = vec![
                Signed {
                    public_key: public_key.clone(),
                    signature: signed[1].signature.clone(),
                    message: seal,
                },
                Signed {
                    public_key,
                    signature: signed[0].signature.clone(),
                    message: b"authorization".to_vec(),
                },
            ];
            assert_rejects(&swapped, "messages swapped between signatures");
        }

        /// The exposed challenge scalar must be the one `verify` uses.
        #[test]
        fn challenge_scalar_matches_verify() {
            let mut rng = rng();
            let (k, public_key) = RistrettoPublicKey::random_keypair(&mut rng);
            let message = b"Thief of Time";
            let signature = RistrettoSchnorr::sign(&k, message, &mut rng).unwrap();

            let e = signature.challenge_scalar(&public_key, message).unwrap();
            assert!(signature.verify_challenge_scalar(&public_key, &e));

            let other = signature.challenge_scalar(&public_key, b"Night Watch").unwrap();
            assert_ne!(e, other);
            assert!(!signature.verify_challenge_scalar(&public_key, &other));
        }

        /// A domain separated signature type must batch under its own domain.
        #[test]
        fn custom_domain() {
            hash_domain!(BatchDomain, "com.tari.test.batch", 1);
            type Sig = RistrettoSchnorrWithDomain<BatchDomain>;

            let mut rng = rng();
            let (k, public_key) = RistrettoPublicKey::random_keypair(&mut rng);
            let message = b"Going Postal";
            let signature = Sig::sign(&k, message, &mut rng).unwrap();

            let items = vec![(&signature, &public_key, message.as_slice())];
            assert!(Sig::verify_batch(&items));
            assert!(Sig::verify_batch_with_rng(&items, &mut rng));

            // A signature over this message under the default domain must not verify here
            let default_domain = RistrettoSchnorr::sign(&k, message, &mut rng).unwrap();
            let crossed = Sig::new(
                default_domain.get_public_nonce().clone(),
                default_domain.get_signature().clone(),
            );
            assert!(!Sig::verify_batch(&[(&crossed, &public_key, message.as_slice())]));
        }
    }

    #[test]
    fn zero_public_key() {
        let mut rng = rand::rng();

        // Generate a zero key
        let secret_key = RistrettoSecretKey::default();
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key);
        assert_eq!(public_key, RistrettoPublicKey::default());

        // Sign a message with the zero key
        let message = "A secret message";
        let sig = RistrettoSchnorr::sign(&secret_key, message, &mut rng).unwrap();

        // The signature should fail to verify
        assert!(!sig.verify(&public_key, message,));
    }
}
