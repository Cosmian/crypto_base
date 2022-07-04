use crate::{
    asymmetric::ristretto::X25519Crypto, symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
    CryptoBaseError, KeyTrait,
};
use rand_core::{CryptoRng, RngCore};

mod block;
mod dem;
mod header;
mod kem;
mod scanner;

pub use block::Block;
pub use dem::Dem;
pub use header::Metadata;
pub use kem::Kem;
pub use scanner::BytesScanner;

pub trait HybridCrypto<T: Kem, U: Dem> {
    fn key_gen<R: RngCore + CryptoRng>(kem: &T, rng: &mut R) -> Result<T::Keys, CryptoBaseError> {
        kem.key_gen(rng)
    }

    fn encrypt<R: RngCore + CryptoRng>(
        kem: &T,
        rng: &mut R,
        pk: &T::PublicKey,
        additional_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        let (secret_key, mut asymmetric_encapsulation) = kem.encaps(rng, pk, U::Key::LENGTH)?;
        let mut symmetric_encapsulation = U::encaps(rng, &secret_key, additional_data, message)?;
        // allocate the correct number of bytes for the ciphertext
        let mut res =
            Vec::with_capacity(T::ENCAPSULATION_SIZE + U::ENCRYPTION_OVERHEAD + message.len());
        res.append(&mut asymmetric_encapsulation);
        res.append(&mut symmetric_encapsulation);
        Ok(res)
    }

    fn decrypt(
        kem: &T,
        sk: &T::PrivateKey,
        additional_data: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        if ciphertext.len() < T::ENCAPSULATION_SIZE {
            return Err(CryptoBaseError::InvalidSize(format!(
                "decrypt: ciphertext has size: {}, it should be at least: {}",
                ciphertext.len(),
                T::ENCAPSULATION_SIZE
            )));
        }
        let secret_key = kem.decaps(sk, &ciphertext[..T::ENCAPSULATION_SIZE], U::Key::LENGTH)?;
        U::decaps(
            &secret_key,
            additional_data,
            &ciphertext[T::ENCAPSULATION_SIZE..],
        )
    }
}

struct HcX25519AesCrypto;
impl HybridCrypto<X25519Crypto, Aes256GcmCrypto> for HcX25519AesCrypto {}
