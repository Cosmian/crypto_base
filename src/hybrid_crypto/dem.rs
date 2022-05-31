use crate::{symmetric_crypto::SymmetricCrypto, Error, KeyTrait};
use rand_core::{CryptoRng, RngCore};

pub trait Dem: SymmetricCrypto {
    /// Number of bytes added to the message length in the ciphertext
    const ENCRYPTION_OVERHEAD: usize = Self::Key::LENGTH + Self::MAC_LENGTH;

    /// Encapsulate data using a KEM-generated secret key `K`.
    ///
    /// - `rng` : secure random number generator
    /// - `secret_key`      : KEM-generated secret key
    /// - `optional_data`   : optional label to use in the authentication method
    /// - `message`         : message to encapsulate
    fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: &[u8],
        additional_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Decapsulate using a KEM-generated secret key `K`.
    ///
    /// - `secret_key`    : KEM-generated secret key
    /// - `optional_data` : optional label to use in the authentication method
    /// - `encapsulation` : encapsulation of the message
    fn decaps(
        secret_key: &[u8],
        additional_data: Option<&[u8]>,
        encapsulation: &[u8],
    ) -> Result<Vec<u8>, Error>;
}
