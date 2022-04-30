#![allow(non_snake_case)]

use crate::{
    asymmetric::{AsymmetricCrypto, KeyPair},
    symmetric_crypto::SymmetricCrypto,
    Error, Key,
};

mod block;
mod dem;
mod header;
mod kem;
mod scanner;

pub use block::Block;
pub use dem::DemAes;
pub use header::{Header, Metadata};
pub use kem::ElGammalKemAesX25519;
pub use scanner::BytesScanner;

/// Key Encapsulation Method (KEM). It is used to generate a secret key along
/// with its encapsulation. This secret key is then typically used in a DEM
/// scheme.
///
/// TODO: should the KDF used be specified here?
pub trait Kem<T: AsymmetricCrypto> {
    /// KEM ciphertext
    type CipherText;

    /// KEM secret key
    type SecretKey;

    /// Generate a new KEM object
    fn new() -> Self;

    /// Describe the scheme in plaintext
    fn description(&self) -> String;

    /// Generate an asymmetric key pair
    fn key_gen(&self) -> <T as AsymmetricCrypto>::KeyPair;

    /// Generate the ciphertext and keying data.
    ///
    /// - `pk`  : public key
    fn encaps(
        &self,
        pk: &<<T as AsymmetricCrypto>::KeyPair as KeyPair>::PublicKey,
    ) -> Result<(Self::CipherText, Self::SecretKey), Error>;

    /// Generate the keying data from the given ciphertext and private key.
    ///
    /// - `sk`  : private key
    /// - `C0`  : ciphertext
    fn decaps(
        &self,
        sk: &<<T as AsymmetricCrypto>::KeyPair as KeyPair>::PrivateKey,
        C0: &Self::CipherText,
    ) -> Result<Self::SecretKey, Error>;
}

pub trait Dem<T: SymmetricCrypto> {
    const KEY_LENGTH: usize = <<T as SymmetricCrypto>::Key as Key>::LENGTH;
    fn new() -> Self;
    fn encrypt(&self, K: &[u8], L: &[u8], m: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, K: &[u8], L: &[u8], c: &[u8]) -> Result<Vec<u8>, Error>;
}
