use crate::{asymmetric::KeyPair, CryptoBaseError};
use cosmian_crypto_core::reexport::generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};

/// Key Encapsulation Method (KEM). It is used to generate a secret key along
/// with its encapsulation. This secret key is then typically used in a DEM
/// scheme.
///
/// TODO: should the KDF used be specified here?
pub trait Kem<SharedSecretLength: ArrayLength<u8>> {
    /// Asymmetric key pair
    type KeyPair: KeyPair;

    /// Number of bytes of the encapsulation
    type EncapsulationSize: ArrayLength<u8>;

    /// Describe the scheme in plaintext
    fn description() -> String;

    /// Generate an asymmetric key pair
    ///
    /// - `rng` : random number generator
    fn key_gen<R: RngCore + CryptoRng>(rng: &mut R) -> Self::KeyPair;

    /// Return `(K, E)` the secret key and its encapsulation.
    ///
    /// - `rng` : random number generator
    /// - `pk`  : public key
    #[allow(clippy::type_complexity)]
    fn encap<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &<Self::KeyPair as KeyPair>::PublicKey,
    ) -> Result<
        (
            GenericArray<u8, SharedSecretLength>,
            GenericArray<u8, Self::EncapsulationSize>,
        ),
        CryptoBaseError,
    >;

    /// Generate the secret key from the given encapsulation and private key.
    ///
    /// - `sk`  : private key
    /// - `E`   : encapsulation
    fn decap(
        sk: &<Self::KeyPair as KeyPair>::PrivateKey,
        encapsulation: GenericArray<u8, Self::EncapsulationSize>,
    ) -> Result<GenericArray<u8, SharedSecretLength>, CryptoBaseError>;
}
