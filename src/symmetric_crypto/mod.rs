#[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
pub mod aes_256_gcm_sodium;
#[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
pub mod xchacha20;

pub use cosmian_crypto_core::symmetric_crypto::{
    aes_256_gcm_pure, nonce, Block, Dem, Metadata, SymmetricCrypto,
};

pub const MIN_DATA_LENGTH: usize = 1;
