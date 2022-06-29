use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoBaseError {
    #[error("Wrong size: {given} given should be {expected}")]
    SizeError { given: usize, expected: usize },
    #[error("Invalid size: {0}")]
    InvalidSize(String),
    #[error("Failed to parse")]
    HexParseError(#[from] hex::FromHexError),
    #[error("Failed to convert: {0}")]
    ConversionError(String),
    #[error("{0}")]
    KdfError(hkdf::InvalidLength),
    #[error("Key generation error")]
    KeyGenError,
    #[error("{0}")]
    EncryptionError(String),
    #[error("{0}")]
    DecryptionError(String),
    #[error("{0}")]
    HardwareCapability(String),
}

impl From<std::array::TryFromSliceError> for CryptoBaseError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        CryptoBaseError::InvalidSize(e.to_string())
    }
}
