use cosmian_crypto_core::CryptoCoreError;
use std::array::TryFromSliceError;
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
