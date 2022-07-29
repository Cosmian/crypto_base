pub mod aes_hash_mmo;
pub mod asymmetric;
pub mod brc_c_prf_hi;
pub mod distributions;
pub mod hybrid_crypto;
pub mod key_wrapping;
pub mod symmetric_crypto;

// this module can be compiled to WASM if need be
#[cfg(all(not(target_arch = "wasm32"), not(windows)))]
pub mod primes;

#[allow(deref_nullptr)]
#[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
pub mod sodium_bindings;

use std::array::TryFromSliceError;

pub use cosmian_crypto_core::entropy;
pub use cosmian_crypto_core::kdf;
use cosmian_crypto_core::CryptoCoreError;
pub use cosmian_crypto_core::KeyTrait;

use thiserror::Error;
#[derive(Debug, Error, PartialEq)]
pub enum CryptoBaseError {
    #[error("{0}")]
    CryptoCoreError(#[from] CryptoCoreError),
    #[error("Failed to parse")]
    HexParseError(#[from] hex::FromHexError),
    #[error("Conversion failed: {0}")]
    ConversionFailed(String),
    #[error("Wrong size: {given} given should be {expected}")]
    SizeError { given: usize, expected: usize },
    #[error("Invalid size")]
    InvalidSize(String),
}

impl From<TryFromSliceError> for CryptoBaseError {
    fn from(e: TryFromSliceError) -> Self {
        Self::ConversionFailed(e.to_string())
    }
}
