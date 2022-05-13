use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Wrong size: {given} given should be {expected}")]
    SizeError { given: usize, expected: usize },
    #[error("Failed to parse")]
    HexParseError(#[from] hex::FromHexError),
    #[error("Failed to convert")]
    ConversionError,
    #[error("{0}")]
    KdfError(hkdf::InvalidLength),
    #[error("Key generation error")]
    KeyGenError,
    #[error("{0}")]
    EncryptionError(String),
    #[error("{0}")]
    DecryptionError(String),
}
