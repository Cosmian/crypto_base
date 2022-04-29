pub mod aes_256_gcm_pure;

#[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
pub mod aes_256_gcm_sodium;

pub mod ff1;

#[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
pub mod xchacha20;

use std::{
    convert::Into,
    fmt::{Debug, Display},
    vec::Vec,
};

use crate::{entropy::CsRng, Error, Key};

pub const MIN_DATA_LENGTH: usize = 1;

pub trait Nonce: Into<Vec<u8>> + Clone + PartialEq + Display + Debug + Sync + Send {
    const LENGTH: usize;
    fn new(rng: &mut CsRng) -> Self;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Error>;
    fn try_from_slice(bytes: &[u8]) -> Result<Self, Error>;
    #[must_use]
    fn increment(&self, increment: usize) -> Self;
    #[must_use]
    fn xor(&self, b2: &[u8]) -> Self;
    fn as_bytes(&self) -> Vec<u8>;
}

pub trait SymmetricCrypto: Send + Sync + Default {
    const MAC_LENGTH: usize;
    type Key: Key;
    type Nonce: Nonce;

    /// Instantiate the symmetric crypto scheme with default parameters
    fn new() -> Self;

    /// A short description of the scheme
    fn description() -> String;

    fn generate_random_bytes(&self, len: usize) -> Vec<u8>;

    // rnd_bytes must be [u8;RANDOM_LENGTH], but this need const generic
    fn generate_key_from_rnd(rnd_bytes: &[u8]) -> Result<Self::Key, Error>;

    fn generate_key(&self) -> Self::Key;

    fn generate_nonce(&self) -> Self::Nonce;

    /// Encrypts a message using a secret key and a public nonce in combined
    /// mode: the encrypted message, as well as a tag authenticating both
    /// the confidential message and non-confidential data, are put into the
    /// encrypted result.
    ///
    /// The total length of the encrypted data is the message length +
    /// `MAC_LENGTH`
    ///
    /// This function encrypts then tag: it can also be used as a MAC, with an
    /// empty message.
    fn encrypt(
        &self,
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>>;

    /// Decrypts a message in combined mode: the MAC is appended to the cipher
    /// text
    ///
    /// The provided additional data must match those provided during encryption
    /// for the MAC to verify.
    ///
    /// Decryption will never be performed, even partially, before verification.
    fn decrypt(
        &self,
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>>;
}
