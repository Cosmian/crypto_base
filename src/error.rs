use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Wrong size: {given} given should be {expected}")]
    SizeError { given: usize, expected: usize },
    #[error("Failed to parse")]
    HexParseError { err: hex::FromHexError },
    #[error("Failed to convert")]
    ConversionError,
    #[error("{err}")]
    KdfError { err: hkdf::InvalidLength },
    #[error("Key generation error")]
    KeyGenError,
    #[error("{err:?}")]
    EncryptionError { err: anyhow::Report },
    #[error("{err:?}")]
    DecryptionError { err: anyhow::Report },
}
