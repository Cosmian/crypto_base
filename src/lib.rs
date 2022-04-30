use rand_core::{CryptoRng, RngCore};
use std::{
    convert::TryFrom,
    fmt::{Debug, Display},
    sync::Mutex,
};
use thiserror::Error;

pub mod aes_hash_mmo;
pub mod asymmetric;
pub mod brc_c_prf_hi;
pub mod entropy;
pub mod hybrid_crypto;
pub mod kdf;
pub mod symmetric_crypto;

// this module can be compiled to WASM if need be
#[cfg(all(not(target_arch = "wasm32"), not(windows)))]
pub mod cs_prng;

// this module can be compiled to WASM if need be
#[cfg(all(not(target_arch = "wasm32"), not(windows)))]
pub mod primes;

#[allow(deref_nullptr)]
#[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
pub mod sodium_bindings;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Wrong size: {given} given should be {expected}")]
    SizeError { given: usize, expected: usize },
    #[error("Failed to parse")]
    ParseError,
    #[error("Failed to convert")]
    ConversionError,
    #[error("{err}")]
    KdfError { err: hkdf::InvalidLength },
    #[error("Key generation error")]
    KeyGenError,
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
}

pub trait Key: TryFrom<Vec<u8>, Error = Error> + PartialEq + Display + Debug + Sync + Send {
    const LENGTH: usize;
    fn new<R: RngCore + CryptoRng>(rng: &Mutex<R>) -> Self;
    fn as_bytes(&self) -> Vec<u8>;
    fn parse(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::try_from(bytes)
    }
}
