mod error;

pub mod aes_hash_mmo;
pub mod asymmetric;
pub mod brc_c_prf_hi;
pub mod entropy;
pub mod hybrid_crypto;
pub mod kdf;
pub mod symmetric_crypto;

// this module can be compiled to WASM if need be
#[cfg(all(not(target_arch = "wasm32"), not(windows)))]
pub mod primes;

#[allow(deref_nullptr)]
#[cfg(all(not(target_arch = "wasm32"), not(windows), feature = "libsodium"))]
pub mod sodium_bindings;

pub use crate::error::CryptoBaseError;

pub trait KeyTrait: Sized + Clone {
    const LENGTH: usize;
    fn to_bytes(&self) -> Vec<u8>;
    fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoBaseError>;
}
