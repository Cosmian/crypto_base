use crate::{CryptoBaseError, KeyTrait};
use rand_core::{CryptoRng, RngCore};

/// Key Encapsulation Method (KEM). It is used to generate a secret key along
/// with its encapsulation. This secret key is then typically used in a DEM
/// scheme.
///
/// TODO: should the KDF used be specified here?
pub trait Kem {
    /// Asymmetric key pair
    type PublicKey: KeyTrait;
    type PrivateKey: KeyTrait;

    /// Result of the key generation, usually a public/private key couple.
    type Keys;

    /// Number of bytes of the encapsulation
    const ENCAPSULATION_SIZE: usize = Self::PublicKey::LENGTH;

    /// Describe the scheme in plaintext
    fn description() -> String;

    /// Generate the KEM public and private keys.
    fn key_gen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Self::Keys, CryptoBaseError>;

    /// Return `(K, E)` the secret key and its encapsulation.
    ///
    /// - `pk`              : public key
    /// - `sym_key_length`  : length in bytes of the generated symmetric key
    fn encaps<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        pk: &Self::PublicKey,
        sym_key_length: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoBaseError>;

    /// Generate the secret key from the given encapsulation and private key.
    ///
    /// - `sk`              : private key
    /// - `E`               : encapsulation
    /// - `sym_key_length`  : the size in bytes of the encapsulated secret key
    fn decaps(
        &self,
        sk: &Self::PrivateKey,
        encapsulation: &[u8],
        sym_key_length: usize,
    ) -> Result<Vec<u8>, CryptoBaseError>;
}
