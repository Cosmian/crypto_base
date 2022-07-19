use crate::{asymmetric::KeyPair, CryptoBaseError};
use cosmian_crypto_base_anssi::KeyTrait;
use rand_core::{CryptoRng, RngCore};

/// Key Encapsulation Method (KEM). It is used to generate a secret key along
/// with its encapsulation. This secret key is then typically used in a DEM
/// scheme.
///
/// TODO: should the KDF used be specified here?
pub trait Kem {
    /// Asymmetric key pair
    type KeyPair: KeyPair;

    /// Number of bytes of the encapsulation
    const ENCAPSULATION_SIZE: usize = <Self::KeyPair as KeyPair>::PublicKey::LENGTH;

    /// Describe the scheme in plaintext
    fn description() -> String;

    /// Generate an asymmetric key pair
    fn key_gen<R: RngCore + CryptoRng>(rng: &mut R) -> Self::KeyPair;

    /// Return `(K, E)` the secret key and its encapsulation.
    ///
    /// - `pk`  : public key
    /// - `secret_key_length`: the size in bytes of the generated secret key
    fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &<Self::KeyPair as KeyPair>::PublicKey,
        secret_key_length: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoBaseError>;

    /// Generate the secret key from the given encapsulation and private key.
    ///
    /// - `sk`  : private key
    /// - `E`   : encapsulation
    /// - `secret_key_length`: the size in bytes of the encapsulated secret key
    fn decaps(
        sk: &<Self::KeyPair as KeyPair>::PrivateKey,
        encapsulation: &[u8],
        secret_key_length: usize,
    ) -> Result<Vec<u8>, CryptoBaseError>;
}
