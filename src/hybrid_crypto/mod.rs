use crate::asymmetric::{ristretto::X25519Crypto, KeyPair};
use cosmian_crypto_base_anssi::{
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem},
    CryptoBaseError, KeyTrait,
};
use rand_core::{CryptoRng, RngCore};

mod kem;

pub use kem::Kem;

pub trait HybridCrypto<T: Kem, U: Dem> {
    fn key_gen<R: RngCore + CryptoRng>(rng: &mut R) -> T::KeyPair {
        T::key_gen(rng)
    }

    fn encrypt<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &<T::KeyPair as KeyPair>::PublicKey,
        additional_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        let (secret_key, mut asymmetric_encapsulation) = T::encaps(rng, pk, U::Key::LENGTH)?;
        let mut symmetric_encapsulation = U::encaps(rng, &secret_key, additional_data, message)?;
        // allocate the correct number of bytes for the ciphertext
        let mut res =
            Vec::with_capacity(T::ENCAPSULATION_SIZE + U::ENCRYPTION_OVERHEAD + message.len());
        res.append(&mut asymmetric_encapsulation);
        res.append(&mut symmetric_encapsulation);
        Ok(res)
    }

    fn decrypt(
        sk: &<T::KeyPair as KeyPair>::PrivateKey,
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
        let secret_key = T::decaps(sk, &ciphertext[..T::ENCAPSULATION_SIZE], U::Key::LENGTH)?;
        U::decaps(
            &secret_key,
            additional_data,
            &ciphertext[T::ENCAPSULATION_SIZE..],
        )
    }
}

struct HcX25519AesCrypto;
impl HybridCrypto<X25519Crypto, Aes256GcmCrypto> for HcX25519AesCrypto {}
