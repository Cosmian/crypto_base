use cosmian_crypto_base_anssi::{
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem},
    CryptoBaseError,
};
use hpke::{kem::X25519HkdfSha256, Deserializable, Kem, Serializable};
use rand_core::{CryptoRng, RngCore};

pub trait HybridCrypto<KEM: Kem, U: Dem> {
    fn key_gen<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(KEM::PrivateKey, KEM::PublicKey), CryptoBaseError> {
        // size of a private key
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Ok(KEM::derive_keypair(&bytes))
    }

    fn encrypt<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &KEM::PublicKey,
        additional_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        let (secret_key, asymmetric_encapsulation) = KEM::encap(pk, None, rng)
            .map_err(|e| CryptoBaseError::EncryptionError(e.to_string()))?;
        let mut symmetric_encapsulation = U::encaps(rng, &secret_key.0, additional_data, message)?;
        let asymmetric_encapsulation = asymmetric_encapsulation.to_bytes();
        // allocate the correct number of bytes for the ciphertext
        let mut res = Vec::with_capacity(
            asymmetric_encapsulation.len() + U::ENCRYPTION_OVERHEAD + message.len(),
        );
        res.extend_from_slice(&asymmetric_encapsulation);
        res.append(&mut symmetric_encapsulation);
        Ok(res)
    }

    fn decrypt(
        sk: &KEM::PrivateKey,
        additional_data: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        if ciphertext.len() < KEM::EncappedKey::size() {
            return Err(CryptoBaseError::SizeError {
                given: ciphertext.len(),
                expected: KEM::EncappedKey::size(),
            });
        }
        let encapsulation = KEM::EncappedKey::from_bytes(&ciphertext[..KEM::EncappedKey::size()])
            .map_err(|e| CryptoBaseError::ConversionError(e.to_string()))?;
        let secret_key = KEM::decap(sk, None, &encapsulation)
            .map_err(|e| CryptoBaseError::DecryptionError(e.to_string()))?;
        U::decaps(
            &secret_key.0,
            additional_data,
            &ciphertext[KEM::EncappedKey::size()..],
        )
    }
}

struct HcX25519AesCrypto;
impl HybridCrypto<X25519HkdfSha256, Aes256GcmCrypto> for HcX25519AesCrypto {}
