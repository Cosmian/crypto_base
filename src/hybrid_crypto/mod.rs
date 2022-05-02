#![allow(non_snake_case)]

use crate::{
    asymmetric::{AsymmetricCrypto, KeyPair},
    symmetric_crypto::SymmetricCrypto,
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

    /// KEM ciphertext
    type Encapsulation;

    /// KEM secret key
    type SecretKey;

    /// Describe the scheme in plaintext
    fn description() -> String;

    /// Generate an asymmetric key pair
    fn key_gen<R: RngCore + CryptoRng>(rng: &Mutex<R>) -> <Self as AsymmetricCrypto>::KeyPair;

    /// Generate the ciphertext and keying data.
    ///
    /// - `pk`  : public key
    fn encaps<R: RngCore + CryptoRng>(
        rng: &Mutex<R>,
        pk: &<<Self as AsymmetricCrypto>::KeyPair as KeyPair>::PublicKey,
    ) -> Result<(Self::Encapsulation, Self::SecretKey), Error>;

    /// Generate the keying data from the given ciphertext and private key.
    ///
    /// - `sk`  : private key
    /// - `C0`  : ciphertext
    fn decaps(
        sk: &<<Self as AsymmetricCrypto>::KeyPair as KeyPair>::PrivateKey,
        E: &Self::Encapsulation,
    ) -> Result<Self::SecretKey, Error>;
}

pub trait Dem: SymmetricCrypto {
    fn encaps<R: RngCore + CryptoRng>(
        rng: &Mutex<R>,
        K: &[u8],
        L: &[u8],
        m: &[u8],
    ) -> Result<Vec<u8>, Error>;
    fn decaps(K: &[u8], L: &[u8], c: &[u8]) -> Result<Vec<u8>, Error>;
}
