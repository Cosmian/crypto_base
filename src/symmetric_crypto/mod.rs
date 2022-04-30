pub mod aes_256_gcm_pure;

#[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
pub mod aes_256_gcm_sodium;

pub mod ff1;

#[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
pub mod xchacha20;

use crate::{Error, Key};
use rand_core::{CryptoRng, RngCore};
use std::{
    convert::TryFrom,
    fmt::{Debug, Display},
    sync::Mutex,
    vec::Vec,
};

pub const MIN_DATA_LENGTH: usize = 1;

pub trait Nonce:
    TryFrom<Vec<u8>, Error = Error> + Clone + PartialEq + Display + Debug + Sync + Send
{
    const LENGTH: usize;
    fn new<R: RngCore + CryptoRng>(rng: &Mutex<R>) -> Self;
    fn try_from_slice(bytes: &[u8]) -> Result<Self, Error>;
    #[must_use]
    fn increment(&self, increment: usize) -> Self;
    #[must_use]
    fn xor(&self, b2: &[u8]) -> Self;
    fn as_bytes(&self) -> Vec<u8>;
}

pub trait SymmetricCrypto: Send + Sync {
    const MAC_LENGTH: usize;
    type Key: Key;
    type Nonce: Nonce;

    /// A short description of the scheme
    fn description() -> String;

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
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>>;
}
