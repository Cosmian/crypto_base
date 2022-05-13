#![allow(non_snake_case)]

use crate::{
    asymmetric::{ristretto::X25519Crypto, AsymmetricCrypto, KeyPair},
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
    Error, KeyTrait,
};

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
    /// Number of bytes of the secret key
    const SECRET_KEY_LENGTH: usize;

    /// Number of bytes of the encapsulation
    const ENCAPSULATION_SIZE: usize = <Self::KeyPair as KeyPair>::PublicKey::LENGTH;

    /// Describe the scheme in plaintext
    fn description() -> String;

    /// Generate an asymmetric key pair
    fn key_gen<R: RngCore + CryptoRng>(rng: &mut R) -> Self::KeyPair;

    /// Return `(K, E)` the secret key and its encapsulation.
    ///
    /// - `pk`  : public key
    fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &<<Self as AsymmetricCrypto>::KeyPair as KeyPair>::PublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>), Error>;

    /// Generate the secret key from the given encapsulation and private key.
    ///
    /// - `sk`  : private key
    /// - `E`   : encapsulation
    fn decaps(
        sk: &<<Self as AsymmetricCrypto>::KeyPair as KeyPair>::PrivateKey,
        E: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

pub trait Dem: SymmetricCrypto {
    /// Number of bytes added to the message length in the ciphertext
    const ENCRYPTION_OVERHEAD: usize = Self::Key::LENGTH + Self::MAC_LENGTH;

    /// Encapsulate data using a KEM-generated secret key `K`.
    ///
    /// - `rng` : secure random number generator
    /// - `K`   : KEM-generated secret key
    /// - `L`   : optional label to use in the authentication method
    /// - `D`   : data to encapsulate
    fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        K: &[u8],
        L: &[u8],
        D: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Decapsulate using a KEM-generated secret key `K`.
    ///
    /// - `K`   : KEM-generated secret key
    /// - `L`   : optional label to use in the authentication method
    /// - `E`   : data encapsulation
    fn decaps(K: &[u8], L: &[u8], E: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait HybridCrypto<T: Kem, U: Dem> {
    fn key_gen<R: RngCore + CryptoRng>(rng: &mut R) -> T::KeyPair {
        T::key_gen(rng)
    }

    fn encrypt<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &<T::KeyPair as KeyPair>::PublicKey,
        L: &[u8],
        m: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (K, mut E1) = T::encaps(rng, pk)?;
        let mut E2 = U::encaps(rng, &K, L, m)?;
        // allocate the correct number of bytes for the ciphertext
        let mut res = Vec::with_capacity(T::ENCAPSULATION_SIZE + U::ENCRYPTION_OVERHEAD + m.len());
        res.append(&mut E1);
        res.append(&mut E2);
        Ok(res)
    }

    fn decrypt(
        sk: &<T::KeyPair as KeyPair>::PrivateKey,
        L: &[u8],
        C: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let K = T::decaps(sk, &C[..T::SECRET_KEY_LENGTH])?;
        U::decaps(&K, L, &C[T::SECRET_KEY_LENGTH..])
    }
}

struct HcX25519AesCrypto;

impl HybridCrypto<X25519Crypto, Aes256GcmCrypto> for HcX25519AesCrypto {}
