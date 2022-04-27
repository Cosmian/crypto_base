#![allow(non_snake_case)]

use crate::{
    asymmetric::{AsymmetricCrypto, KeyPair},
    Error,
};

mod block;
mod header;
mod kem;
mod scanner;

pub use block::Block;
pub use header::{Header, Metadata};
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
    fn key_gen(&self) -> Result<<T as AsymmetricCrypto>::KeyPair, Error>;

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
