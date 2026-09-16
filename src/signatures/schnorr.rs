// Copyright 2022. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Schnorr Signature module
//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::{Add, Mul},
};

use blake2::Blake2b;
use digest::{Digest, consts::U64};
use rand_core::{CryptoRng, Rng};
use snafu::prelude::*;
use tari_utilities::ByteArray;

use crate::{
    hash_domain,
    hashing::{DomainSeparatedHash, DomainSeparatedHasher, DomainSeparation},
    keys::{PublicKey, SecretKey},
};

// Define a default hashing domain for Schnorr signatures
// You almost certainly want to define your own that is specific to signature context!
hash_domain!(SchnorrSigChallenge, "com.tari.schnorr_signature", 1);

/// The number of bytes of entropy in each batch verification weight.
///
/// The weights are 128-bit with the top bit forced set, which bounds the soundness error of a batch at `2^-127`.
const BATCH_WEIGHT_LEN: usize = 16;

/// How many batch verification weights fit into a single 64-byte digest.
const WEIGHTS_PER_DIGEST: usize = 64 / BATCH_WEIGHT_LEN;

/// An error occurred during construction of a SchnorrSignature
#[derive(Clone, Debug, Snafu, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(missing_docs)]
pub enum SchnorrSignatureError {
    #[snafu(display("An invalid challenge was provided"))]
    InvalidChallenge,
}

/// # SchnorrSignature
///
/// Provides a Schnorr signature that is agnostic to a specific public/private key implementation.
/// For a concrete implementation see [RistrettoSchnorr](crate::ristretto::RistrettoSchnorr).
///
/// More details on Schnorr signatures can be found at [TLU](https://tlu.tarilabs.com/cryptography/introduction-schnorr-signatures).
#[allow(non_snake_case)]
#[derive(Copy, Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SchnorrSignature<P, K, H = SchnorrSigChallenge> {
    pub(crate) public_nonce: P,
    pub(crate) signature: K,
    #[cfg_attr(feature = "serde", serde(skip))]
    _phantom: PhantomData<H>,
}

impl<P, K, H> SchnorrSignature<P, K, H>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    H: DomainSeparation,
{
    /// Create a new `SchnorrSignature`.
    pub fn new(public_nonce: P, signature: K) -> Self {
        SchnorrSignature {
            public_nonce,
            signature,
            _phantom: PhantomData,
        }
    }

    /// Calculates the signature verifier `s.G`. This must be equal to `R + eK`.
    fn calc_signature_verifier(&self) -> P {
        P::from_secret_key(&self.signature)
    }

    /// Generate a signature using a given secret key, nonce, and challenge byte slice.
    ///
    /// WARNING: This is intended for use cases where the challenge byte slice was generated correctly.
    /// In particlar, it _must_ be the result of securely applying a cryptographic hash function to the correct public
    /// key, public nonce, and input message; further, it must be of a length suitable for scalar wide reduction.
    /// This function only checks that the byte slice is of the correct length.
    /// The nonce _must_ also have been sampled uniformly at random and not reused with the same secret key and a
    /// different message.
    ///
    /// If you aren't sure that you can meet these requirements, and want a simple and safe API, use [`sign`].
    pub fn sign_raw_uniform<'a>(secret: &'a K, nonce: K, challenge: &[u8]) -> Result<Self, SchnorrSignatureError>
    where K: Add<Output = K> + Mul<&'a K, Output = K> {
        // s = r + e.k
        let e = match K::from_uniform_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return Err(SchnorrSignatureError::InvalidChallenge),
        };
        let public_nonce = P::from_secret_key(&nonce);
        let ek = e * secret;
        let s = ek + nonce;
        Ok(Self::new(public_nonce, s))
    }

    /// Generate a signature using a given secret key, nonce, and challenge byte slice.
    ///
    /// WARNING: This is intended for use cases where the challenge byte slice was generated correctly.
    /// In particlar, it _must_ be the result of securely applying a cryptographic hash function to the correct public
    /// key, public nonce, and input message; further, it must be the canonical representation of a scalar.
    /// This function only checks that the byte slice is of the correct length.
    /// The nonce _must_ also have been sampled uniformly at random and not reused with the same secret key and a
    /// different message.
    ///
    /// If you aren't sure that you can meet these requirements, and want a simple and safe API, use [`sign`].
    pub fn sign_raw_canonical<'a>(secret: &'a K, nonce: K, challenge: &[u8]) -> Result<Self, SchnorrSignatureError>
    where K: Add<Output = K> + Mul<&'a K, Output = K> {
        // s = r + e.k
        let e = match K::from_canonical_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return Err(SchnorrSignatureError::InvalidChallenge),
        };
        let public_nonce = P::from_secret_key(&nonce);
        let ek = e * secret;
        let s = ek + nonce;
        Ok(Self::new(public_nonce, s))
    }

    /// Signs a message with the given secret key.
    ///
    /// This method correctly binds a nonce and the public key to the signature challenge, using domain-separated
    /// hashing. The hasher is also opinionated in the sense that Blake2b 512-bit digest is always used.
    pub fn sign<'a, B, R: Rng + CryptoRng>(
        secret: &'a K,
        message: B,
        rng: &mut R,
    ) -> Result<Self, SchnorrSignatureError>
    where
        K: Add<Output = K> + Mul<&'a K, Output = K>,
        B: AsRef<[u8]>,
    {
        let nonce = K::random(rng);
        Self::sign_with_nonce_and_message(secret, nonce, message)
    }

    /// Signs a message with the given secret key and nonce.
    ///
    /// This method correctly binds the nonce and the public key to the signature challenge, using domain-separated
    /// hashing. The hasher is also opinionated in the sense that Blake2b 512-bit digest is always used.
    ///
    /// WARNING: The nonce _must_ also have been sampled uniformly at random and not reused with the same secret key and
    /// a different message.
    pub fn sign_with_nonce_and_message<'a, B>(
        secret: &'a K,
        nonce: K,
        message: B,
    ) -> Result<Self, SchnorrSignatureError>
    where
        K: Add<Output = K> + Mul<&'a K, Output = K>,
        B: AsRef<[u8]>,
    {
        let public_nonce = P::from_secret_key(&nonce);
        let public_key = P::from_secret_key(secret);
        let challenge =
            Self::construct_domain_separated_challenge::<_, Blake2b<U64>>(&public_nonce, &public_key, message);
        Self::sign_raw_uniform(secret, nonce, challenge.as_ref())
    }

    /// Constructs an opinionated challenge hash for the given public nonce, public key and message.
    ///
    /// In general, the signature challenge is given by `H(R, P, m)`. Often, plain concatenation is used to construct
    /// the challenge. In this implementation, the challenge is constructed by means of domain separated hashing
    /// using the provided digest.
    ///
    /// This challenge is used in the [`sign_message`] and [`verify_message`] methods. If you wish to use a custom
    /// challenge, you can use [`sign_raw_canonical`] or [`sign_raw_wide`] instead.
    pub fn construct_domain_separated_challenge<B, D>(
        public_nonce: &P,
        public_key: &P,
        message: B,
    ) -> DomainSeparatedHash<D>
    where
        B: AsRef<[u8]>,
        D: Digest,
    {
        DomainSeparatedHasher::<D, H>::new_with_label("challenge")
            .chain(public_nonce.as_bytes())
            .chain(public_key.as_bytes())
            .chain(message.as_ref())
            .finalize()
    }

    /// Verifies a signature created by the `sign` method. The function returns `true` if and only if the
    /// message was signed by the secret key corresponding to the given public key, and that the challenge was
    /// constructed using the domain-separation method defined in [`construct_domain_separated_challenge`].
    pub fn verify<'a, B>(&self, public_key: &'a P, message: B) -> bool
    where
        for<'b> &'b K: Mul<&'a P, Output = P>,
        for<'b> &'b P: Add<P, Output = P>,
        B: AsRef<[u8]>,
    {
        let challenge =
            Self::construct_domain_separated_challenge::<_, Blake2b<U64>>(&self.public_nonce, public_key, message);
        self.verify_raw_uniform(public_key, challenge.as_ref())
    }

    /// Verifies a signature against a given public key and challenge byte slice.
    /// The byte slice is converted to a scalar using wide reduction.
    pub fn verify_raw_uniform<'a>(&self, public_key: &'a P, challenge: &[u8]) -> bool
    where
        for<'b> &'b K: Mul<&'a P, Output = P>,
        for<'b> &'b P: Add<P, Output = P>,
    {
        let e = match K::from_uniform_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return false,
        };
        self.verify_challenge_scalar(public_key, &e)
    }

    /// Verifies a signature against a given public key and challenge byte slice.
    /// The byte slice is converted to a scalar assuming a canonical representation.
    pub fn verify_raw_canonical<'a>(&self, public_key: &'a P, challenge: &[u8]) -> bool
    where
        for<'b> &'b K: Mul<&'a P, Output = P>,
        for<'b> &'b P: Add<P, Output = P>,
    {
        let e = match K::from_canonical_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return false,
        };
        self.verify_challenge_scalar(public_key, &e)
    }

    /// Returns true if this signature is valid for a public key and challenge scalar, otherwise false.
    pub fn verify_challenge_scalar<'a>(&self, public_key: &'a P, challenge: &K) -> bool
    where
        for<'b> &'b K: Mul<&'a P, Output = P>,
        for<'b> &'b P: Add<P, Output = P>,
    {
        // Reject a zero key
        if public_key == &P::default() {
            return false;
        }

        let lhs = self.calc_signature_verifier();
        let rhs = &self.public_nonce + challenge * public_key;
        // Implementors should make this a constant time comparison
        lhs == rhs
    }

    /// Returns the challenge scalar `e = H(R, P, m)` that [`SchnorrSignature::verify`] checks this signature
    /// against.
    ///
    /// This is exactly the derivation used by [`SchnorrSignature::sign`] and [`SchnorrSignature::verify`]: the
    /// domain separated Blake2b-512 challenge of [`SchnorrSignature::construct_domain_separated_challenge`],
    /// wide-reduced into a scalar. It is exposed so that callers building their own verification equations do not
    /// have to reproduce it.
    pub fn challenge_scalar<B>(&self, public_key: &P, message: B) -> Result<K, SchnorrSignatureError>
    where B: AsRef<[u8]> {
        let challenge =
            Self::construct_domain_separated_challenge::<_, Blake2b<U64>>(&self.public_nonce, public_key, message);
        K::from_uniform_bytes(challenge.as_ref()).map_err(|_| SchnorrSignatureError::InvalidChallenge)
    }

    /// Verifies a batch of signatures created by the [`SchnorrSignature::sign`] method in variable time, using
    /// weights derived deterministically from the batch itself.
    ///
    /// Each item is a `(signature, public key, message)` triple, and the result is `true` if and only if every
    /// signature in the batch would individually verify under [`SchnorrSignature::verify`]. An empty batch
    /// verifies vacuously.
    ///
    /// Given `eᵢ = H(Rᵢ, Pᵢ, mᵢ)` and weights `zᵢ`, this checks the single equation
    ///
    /// ```text
    /// Σ zᵢ·Rᵢ + Σ (zᵢ·eᵢ)·Pᵢ == (Σ zᵢ·sᵢ)·G
    /// ```
    ///
    /// which is a `2n`-term multiscalar multiplication instead of `n` independent verifications. The weights stop a
    /// set of individually invalid signatures from cancelling one another out.
    ///
    /// The weights here are a domain separated hash of the whole batch, so every caller reaches the same verdict on
    /// the same bytes and no local randomness is required; this is the variant to use for consensus. Soundness is
    /// the Fiat-Shamir argument: forging a set whose defects cancel under its own weights is a `2^127` search. If
    /// you do not need reproducibility across callers, prefer [`SchnorrSignature::verify_batch_with_rng`].
    ///
    /// Every input is public data, so the variable-time multiscalar multiplication this relies on is safe; do not
    /// hand this function secret keys.
    ///
    /// Only a `bool` is returned. Naming the offending index would need a double-base multiplication per term,
    /// making a rejected batch cost more than an accepted one; callers that need the culprit should fall back to
    /// [`SchnorrSignature::verify`] in a loop.
    pub fn verify_batch<B>(items: &[(&Self, &P, B)]) -> bool
    where
        B: AsRef<[u8]>,
        for<'a> &'a K: Mul<&'a K, Output = K>,
    {
        if items.is_empty() {
            return true;
        }
        let Some(weights) = Self::deterministic_batch_weights(items) else {
            return false;
        };
        Self::verify_batch_with_weights(items, &weights)
    }

    /// Verifies a batch of signatures created by the [`SchnorrSignature::sign`] method in variable time, using
    /// weights drawn from `rng`.
    ///
    /// This is [`SchnorrSignature::verify_batch`] with randomly sampled rather than hash-derived weights, giving a
    /// soundness error of `2^-127` per batch. Because the verdict depends on local randomness it must not be used
    /// where several parties have to agree on it; use [`SchnorrSignature::verify_batch`] for that.
    pub fn verify_batch_with_rng<B, R>(items: &[(&Self, &P, B)], rng: &mut R) -> bool
    where
        B: AsRef<[u8]>,
        R: Rng + CryptoRng,
        for<'a> &'a K: Mul<&'a K, Output = K>,
    {
        if items.is_empty() {
            return true;
        }
        let mut weights = Vec::with_capacity(items.len());
        for _ in 0..items.len() {
            let mut bytes = [0u8; BATCH_WEIGHT_LEN];
            rng.fill_bytes(&mut bytes);
            match Self::batch_weight_from_bytes(bytes) {
                Some(weight) => weights.push(weight),
                None => return false,
            }
        }
        Self::verify_batch_with_weights(items, &weights)
    }

    /// Checks the batch equation for a set of items against a set of weights.
    fn verify_batch_with_weights<B>(items: &[(&Self, &P, B)], weights: &[K]) -> bool
    where
        B: AsRef<[u8]>,
        for<'a> &'a K: Mul<&'a K, Output = K>,
    {
        debug_assert_eq!(items.len(), weights.len());

        let identity = P::default();
        let mut scalars = Vec::with_capacity(2 * items.len());
        let mut points = Vec::with_capacity(2 * items.len());
        let mut signature_sum = K::default();

        for ((signature, public_key, message), weight) in items.iter().zip(weights) {
            // Reject a zero key. Under `P = 0` the batch equation degenerates to `s·G == R`, which anyone can
            // satisfy, and the batch never falls through to the per-signature check that would refuse it.
            if **public_key == identity {
                return false;
            }
            let Ok(e) = signature.challenge_scalar(public_key, message) else {
                return false;
            };

            signature_sum = signature_sum + (weight * &signature.signature);
            scalars.push(weight.clone());
            points.push(signature.public_nonce.clone());
            scalars.push(weight * &e);
            points.push((*public_key).clone());
        }

        // Σ zᵢ·Rᵢ + Σ (zᵢ·eᵢ)·Pᵢ == (Σ zᵢ·sᵢ)·G
        P::vartime_batch_mul(&scalars, &points) == P::from_secret_key(&signature_sum)
    }

    /// Derives one weight per item from a domain separated hash of the entire batch.
    ///
    /// The transcript commits to the batch length and then to every `(mᵢ, Pᵢ, Rᵢ, sᵢ)` in order.
    /// [`DomainSeparatedHasher::update`] length-prefixes each field, so a variable-length message cannot be shifted
    /// across a field boundary to make two distinct batches share a transcript. The resulting seed is expanded a
    /// digest at a time, each one yielding [`WEIGHTS_PER_DIGEST`] weights.
    fn deterministic_batch_weights<B>(items: &[(&Self, &P, B)]) -> Option<Vec<K>>
    where B: AsRef<[u8]> {
        let mut transcript = DomainSeparatedHasher::<Blake2b<U64>, H>::new_with_label("batch_weight");
        transcript.update((items.len() as u64).to_le_bytes());
        for (signature, public_key, message) in items {
            transcript.update(message.as_ref());
            transcript.update(public_key.as_bytes());
            transcript.update(signature.public_nonce.as_bytes());
            transcript.update(signature.signature.as_bytes());
        }
        let seed = transcript.finalize();

        let mut weights = Vec::with_capacity(items.len());
        for block in 0..items.len().div_ceil(WEIGHTS_PER_DIGEST) {
            let digest = DomainSeparatedHasher::<Blake2b<U64>, H>::new_with_label("batch_weight_expand")
                .chain(seed.as_ref())
                .chain((block as u64).to_le_bytes())
                .finalize();
            for bytes in digest.as_ref().as_chunks::<BATCH_WEIGHT_LEN>().0 {
                if weights.len() == items.len() {
                    break;
                }
                weights.push(Self::batch_weight_from_bytes(*bytes)?);
            }
        }

        Some(weights)
    }

    /// Turns [`BATCH_WEIGHT_LEN`] bytes of entropy into a non-zero batch weight.
    fn batch_weight_from_bytes(mut bytes: [u8; BATCH_WEIGHT_LEN]) -> Option<K> {
        // Force the top bit so the weight can never be zero; a zero weight would silently drop its term from the
        // batch equation, letting an invalid signature through.
        bytes[BATCH_WEIGHT_LEN - 1] |= 0b1000_0000;

        // Scalars are little-endian, so putting the entropy in the low bytes of an otherwise zero wide-reduction
        // buffer yields exactly the 128-bit integer it encodes: any sane group order is far larger than 2^128, so
        // the reduction is the identity here.
        let mut wide = vec![0u8; K::WIDE_REDUCTION_LEN];
        wide.get_mut(..BATCH_WEIGHT_LEN)?.copy_from_slice(&bytes);
        K::from_uniform_bytes(&wide).ok()
    }

    /// Returns a reference to the `s` signature component.
    pub fn get_signature(&self) -> &K {
        &self.signature
    }

    /// Returns a reference to the public nonce component.
    pub fn get_public_nonce(&self) -> &P {
        &self.public_nonce
    }
}

impl<'a, 'b, P, K, H> Add<&'b SchnorrSignature<P, K>> for &'a SchnorrSignature<P, K, H>
where
    P: PublicKey<K = K>,
    &'a P: Add<&'b P, Output = P>,
    K: SecretKey,
    &'a K: Add<&'b K, Output = K>,
    H: DomainSeparation,
{
    type Output = SchnorrSignature<P, K>;

    fn add(self, rhs: &'b SchnorrSignature<P, K>) -> SchnorrSignature<P, K> {
        let r_sum = self.get_public_nonce() + rhs.get_public_nonce();
        let s_sum = self.get_signature() + rhs.get_signature();
        SchnorrSignature::new(r_sum, s_sum)
    }
}

impl<'a, P, K, H> Add<SchnorrSignature<P, K>> for &'a SchnorrSignature<P, K, H>
where
    P: PublicKey<K = K>,
    for<'b> &'a P: Add<&'b P, Output = P>,
    K: SecretKey,
    for<'b> &'a K: Add<&'b K, Output = K>,
    H: DomainSeparation,
{
    type Output = SchnorrSignature<P, K>;

    fn add(self, rhs: SchnorrSignature<P, K>) -> SchnorrSignature<P, K> {
        let r_sum = self.get_public_nonce() + rhs.get_public_nonce();
        let s_sum = self.get_signature() + rhs.get_signature();
        SchnorrSignature::new(r_sum, s_sum)
    }
}

impl<P, K, H> Default for SchnorrSignature<P, K, H>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    H: DomainSeparation,
{
    fn default() -> Self {
        SchnorrSignature::new(P::default(), K::default())
    }
}

impl<P, K, H> Ord for SchnorrSignature<P, K, H>
where
    P: Eq + Ord,
    K: Eq + ByteArray,
{
    /// Provide an efficient ordering algorithm for Schnorr signatures. It's probably not a good idea to implement `Ord`
    /// for secret keys, but in this instance, the signature is publicly known and is simply a scalar, so we use the
    /// byte representation of the scalar as the canonical ordering metric. This conversion is done if and only if
    /// the public nonces are already equal, otherwise the public nonce ordering determines the SchnorrSignature
    /// order.
    fn cmp(&self, other: &Self) -> Ordering {
        match self.public_nonce.cmp(&other.public_nonce) {
            Ordering::Equal => self.signature.as_bytes().cmp(other.signature.as_bytes()),
            v => v,
        }
    }
}

impl<P, K, H> PartialOrd for SchnorrSignature<P, K, H>
where
    P: Eq + Ord,
    K: Eq + ByteArray,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P, K, H> Eq for SchnorrSignature<P, K, H>
where
    P: Eq,
    K: Eq,
{
}

impl<P, K, H> PartialEq for SchnorrSignature<P, K, H>
where
    P: PartialEq,
    K: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.public_nonce.eq(&other.public_nonce) && self.signature.eq(&other.signature)
    }
}

impl<P, K, H> Hash for SchnorrSignature<P, K, H>
where
    P: Hash,
    K: Hash,
{
    fn hash<T: Hasher>(&self, state: &mut T) {
        self.public_nonce.hash(state);
        self.signature.hash(state);
    }
}

#[cfg(test)]
mod test {
    use alloc::vec::Vec;

    use tari_utilities::ByteArray;

    use super::{BATCH_WEIGHT_LEN, WEIGHTS_PER_DIGEST};
    use crate::{
        hashing::DomainSeparation,
        keys::{PublicKey, SecretKey},
        ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
        signatures::SchnorrSigChallenge,
    };

    #[test]
    fn schnorr_hash_domain() {
        assert_eq!(SchnorrSigChallenge::domain(), "com.tari.schnorr_signature");
        assert_eq!(
            SchnorrSigChallenge::domain_separation_tag("test"),
            "com.tari.schnorr_signature.v1.test"
        );
    }

    #[test]
    fn batch_weights_are_never_zero() {
        let zero = RistrettoSecretKey::default();
        for bytes in [[0u8; BATCH_WEIGHT_LEN], [0xff; BATCH_WEIGHT_LEN]] {
            let weight = RistrettoSchnorr::batch_weight_from_bytes(bytes).unwrap();
            assert_ne!(weight, zero);
        }
    }

    /// The weight is the little-endian 128-bit integer the bytes encode, with the top bit forced set.
    #[test]
    fn batch_weight_encoding() {
        let mut bytes = [0u8; BATCH_WEIGHT_LEN];
        bytes[0] = 7;
        let weight = RistrettoSchnorr::batch_weight_from_bytes(bytes).unwrap();

        let mut expected = [0u8; 32];
        expected[0] = 7;
        expected[BATCH_WEIGHT_LEN - 1] = 0b1000_0000;
        assert_eq!(weight.as_bytes(), &expected);
    }

    struct Signed {
        public_key: RistrettoPublicKey,
        signature: RistrettoSchnorr,
        message: Vec<u8>,
    }

    fn sign_n(n: usize) -> Vec<Signed> {
        let mut rng = rand::rng();
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

    fn weights(signed: &[Signed]) -> Vec<RistrettoSecretKey> {
        let items: Vec<_> = signed
            .iter()
            .map(|s| (&s.signature, &s.public_key, s.message.as_slice()))
            .collect();
        RistrettoSchnorr::deterministic_batch_weights(&items).unwrap()
    }

    /// Every node must derive the same weights from the same bytes, one per item, however the digest blocks fall.
    #[test]
    fn deterministic_weights_are_stable() {
        for n in [1usize, 2, 3, WEIGHTS_PER_DIGEST, WEIGHTS_PER_DIGEST + 1, 33] {
            let signed = sign_n(n);
            let first = weights(&signed);
            assert_eq!(first.len(), n);
            assert_eq!(first, weights(&signed));

            // Distinct items must not share a weight
            for i in 0..n {
                for j in 0..i {
                    assert_ne!(first[i], first[j], "n = {n}, i = {i}, j = {j}");
                }
            }
        }
    }

    /// Changing any part of any term must change the weights, or a swapped batch could reuse a transcript.
    #[test]
    fn deterministic_weights_change_with_the_batch() {
        let mut rng = rand::rng();
        let signed = sign_n(3);
        let baseline = weights(&signed);

        // A different message
        let mut altered: Vec<Signed> = signed
            .iter()
            .map(|s| Signed {
                public_key: s.public_key.clone(),
                signature: s.signature.clone(),
                message: s.message.clone(),
            })
            .collect();
        altered[1].message = b"something else".to_vec();
        assert_ne!(weights(&altered), baseline);

        // A different public key
        altered[1].message = signed[1].message.clone();
        altered[1].public_key = RistrettoPublicKey::random_keypair(&mut rng).1;
        assert_ne!(weights(&altered), baseline);

        // A different public nonce
        altered[1].public_key = signed[1].public_key.clone();
        altered[1].signature = RistrettoSchnorr::new(
            RistrettoPublicKey::random_keypair(&mut rng).1,
            signed[1].signature.get_signature().clone(),
        );
        assert_ne!(weights(&altered), baseline);

        // A different signature scalar
        altered[1].signature = RistrettoSchnorr::new(
            signed[1].signature.get_public_nonce().clone(),
            RistrettoSecretKey::random(&mut rng),
        );
        assert_ne!(weights(&altered), baseline);

        // A shorter batch
        altered[1].signature = signed[1].signature.clone();
        assert_eq!(weights(&altered), baseline);
        altered.pop();
        assert_ne!(weights(&altered), baseline[..2]);

        // And the order of the batch
        let reversed: Vec<Signed> = signed
            .iter()
            .rev()
            .map(|s| Signed {
                public_key: s.public_key.clone(),
                signature: s.signature.clone(),
                message: s.message.clone(),
            })
            .collect();
        assert_ne!(weights(&reversed), baseline);
    }
}
