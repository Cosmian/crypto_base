#![allow(non_snake_case)]

use crate::{
    asymmetric::{ristretto::X25519Crypto, AsymmetricCrypto, KeyPair},
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
    Error,
};
use std::sync::Mutex;

mod block;
mod dem;
mod header;
mod kem;
mod scanner;

pub use block::Block;
pub use header::{Header, Metadata};
use rand_core::{CryptoRng, RngCore};
pub use scanner::BytesScanner;

/// Key Encapsulation Method (KEM). It is used to generate a secret key along
/// with its encapsulation. This secret key is then typically used in a DEM
/// scheme.
///
/// TODO: should the KDF used be specified here?
pub trait Kem: AsymmetricCrypto {
    /// Length of the sescret key
    const KEY_LENGTH: usize;

    /// Describe the scheme in plaintext
    fn description() -> String;

    /// Generate an asymmetric key pair
    fn key_gen<R: RngCore + CryptoRng>(rng: &Mutex<R>) -> Self::KeyPair;

    /// Generate the secret key and its encapsulation.
    ///
    /// - `pk`  : public key
    fn encaps<R: RngCore + CryptoRng>(
        rng: &Mutex<R>,
        pk: &<<Self as AsymmetricCrypto>::KeyPair as KeyPair>::PublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), Error>;

    /// Generate the keying data from the given ciphertext and private key.
    ///
    /// - `sk`  : private key
    /// - `E`   : encapsulation
    fn decaps(
        sk: &<<Self as AsymmetricCrypto>::KeyPair as KeyPair>::PrivateKey,
        E: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

pub trait Dem: SymmetricCrypto {
    /// Encapsulate data using a KEM-generated secret key `K`.
    ///
    /// - `rng` : secure random number generator
    /// - `K`   : KEM-generated secret key
    /// - `L`   : optional label to use in the authentification method
    /// - `D`   : data to encapsulate
    fn encaps<R: RngCore + CryptoRng>(
        rng: &Mutex<R>,
        K: &[u8],
        L: &[u8],
        D: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Decapsulate using a KEM-generated secret key `K`.
    ///
    /// - `K`   : KEM-generated secret key
    /// - `L`   : optional label to use in the authentification method
    /// - `E`   : data encapsulation
    fn decaps(K: &[u8], L: &[u8], E: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait HybrideCrypto<T: Kem, U: Dem> {
    fn key_gen<R: RngCore + CryptoRng>(rng: &Mutex<R>) -> T::KeyPair {
        T::key_gen(rng)
    }

    fn encrypt<R: RngCore + CryptoRng>(
        rng: &Mutex<R>,
        pk: &<T::KeyPair as KeyPair>::PublicKey,
        L: &[u8],
        m: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (K, mut C) = T::encaps(rng, pk)?;
        C.append(&mut U::encaps(rng, &K, L, m)?);
        Ok(C)
    }

    fn decrypt(
        sk: &<T::KeyPair as KeyPair>::PrivateKey,
        L: &[u8],
        C: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let K = T::decaps(sk, &C[..T::KEY_LENGTH])?;
        U::decaps(&K, L, &C[T::KEY_LENGTH..])
    }
}

struct HcX25519AesCrypto;

impl HybrideCrypto<X25519Crypto, Aes256GcmCrypto> for HcX25519AesCrypto {}
