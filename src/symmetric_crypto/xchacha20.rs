use crate::{
    sodium_bindings::{
        crypto_aead_xchacha20poly1305_ietf_ABYTES, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, crypto_aead_xchacha20poly1305_ietf_decrypt,
        crypto_aead_xchacha20poly1305_ietf_encrypt, sodium_init,
    },
    symmetric_crypto::{SymmetricCrypto, MIN_DATA_LENGTH},
    CryptoBaseError,
};
use std::sync::Once;
use std::vec::Vec;

static START: Once = Once::new();

pub const KEY_LENGTH: usize = crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;
pub const NONCE_LENGTH: usize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize;
pub const MAC_LENGTH: usize = crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;

pub type Key = crate::symmetric_crypto::key::Key<KEY_LENGTH>;
pub type Nonce = crate::symmetric_crypto::nonce::Nonce<NONCE_LENGTH>;

#[derive(Debug, PartialEq)]
pub struct XChacha20Crypto;

impl SymmetricCrypto for XChacha20Crypto {
    type Key = Key;
    type Nonce = Nonce;

    const MAC_LENGTH: usize = MAC_LENGTH;

    fn description() -> String {
        format!(
            "XChaCha20 Poly1305 libsodium (key bits: {}, nonce bits: {}, mac bits: {})",
            KEY_LENGTH * 8,
            NONCE_LENGTH * 8,
            MAC_LENGTH * 8
        )
    }

    fn decrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        START.call_once(|| unsafe {
            sodium_init();
        });

        if bytes.is_empty() {
            return Ok(vec![]);
        }
        if bytes.len() < MAC_LENGTH + MIN_DATA_LENGTH {
            return Err(CryptoBaseError::DecryptionError(
                "Not enough data for XChaCha20 decryption".to_string(),
            ));
        }
        let clear_text_length = bytes.len() - MAC_LENGTH;
        let mut result = vec![0; clear_text_length];
        unsafe {
            let (ad, ad_len) = match additional_data {
                Some(b) => (b.as_ptr(), b.len() as u64),
                None => (std::ptr::null(), 0_u64),
            };
            let res = crypto_aead_xchacha20poly1305_ietf_decrypt(
                result.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u64,
                ad,
                ad_len,
                nonce.0.as_ref().as_ptr(),
                key.0.as_ptr(),
            );
            if res != 0 {
                return Err(CryptoBaseError::DecryptionError(
                    "XChaCha20 decryption failed".to_string(),
                ));
            }
        }
        Ok(result)
    }

    fn encrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        START.call_once(|| unsafe {
            sodium_init();
        });

        let (ad, ad_len) = match additional_data {
            Some(b) => (b.as_ptr(), b.len() as u64),
            None => (std::ptr::null(), 0_u64),
        };
        let cipher_length = bytes.len() + MAC_LENGTH;
        let mut result: Vec<u8> = vec![0; cipher_length];
        unsafe {
            let res = crypto_aead_xchacha20poly1305_ietf_encrypt(
                result.as_mut_ptr(),
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u64,
                ad,
                ad_len,
                std::ptr::null(),
                nonce.0.as_ref().as_ptr(),
                key.0.as_ptr(),
            );
            if res != 0 {
                return Err(CryptoBaseError::EncryptionError(
                    "XChaCha20 encryption failed".to_string(),
                ));
            };
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::{entropy::CsRng, symmetric_crypto::nonce::NonceTrait};

    use super::{
        Key, Nonce, SymmetricCrypto, XChacha20Crypto, KEY_LENGTH, MAC_LENGTH, NONCE_LENGTH,
    };

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::new();
        let key_1 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_1.0.len());
        let key_2 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_2.0.len());
        assert_ne!(key_1, key_2);
    }

    #[test]
    fn test_nonce() {
        let mut cs_rng = CsRng::new();
        let nonce_1 = Nonce::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_1.0.len());
        let nonce_2 = Nonce::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_2.0.len());
        assert_ne!(nonce_1, nonce_2);
    }

    #[test]
    fn test_encryption_decryption_xchacha20() {
        let mut cs_rng = CsRng::new();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes(8192);
        let ad = cs_rng.generate_random_bytes(56);
        let iv = Nonce::new(&mut cs_rng);
        let encrypted_result = XChacha20Crypto::encrypt(&key, &bytes, &iv, Some(&ad)).unwrap();
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        // decrypt
        let recovered =
            XChacha20Crypto::decrypt(&key, encrypted_result.as_slice(), &iv, Some(&ad)).unwrap();
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn test_encryption_decryption_xchacha20_chunks() {
        let mut cs_rng = CsRng::new();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes(10000);
        let ad = cs_rng.generate_random_bytes(92);
        let iv = Nonce::new(&mut cs_rng);

        let mut encrypted_result: Vec<u8> = vec![];
        encrypted_result.extend_from_slice(
            &XChacha20Crypto::encrypt(&key, &bytes[..4096], &iv, Some(&ad)).unwrap(),
        );
        let mut next_nonce = iv.increment(1);
        encrypted_result.extend_from_slice(
            &XChacha20Crypto::encrypt(&key, &bytes[4096..8192], &next_nonce, Some(&ad)).unwrap(),
        );
        next_nonce = next_nonce.increment(1);
        encrypted_result.extend_from_slice(
            &XChacha20Crypto::encrypt(&key, &bytes[8192..], &next_nonce, Some(&ad)).unwrap(),
        );
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + 3 * MAC_LENGTH, encrypted_result.len());
        // decrypt
        let mut recovered: Vec<u8> = vec![];
        recovered.extend_from_slice(
            &XChacha20Crypto::decrypt(&key, &encrypted_result[..4096 + MAC_LENGTH], &iv, Some(&ad))
                .unwrap(),
        );
        let mut next_nonce = iv.increment(1);
        assert_eq!(bytes[..4096], recovered[..4096]);
        recovered.extend_from_slice(
            &XChacha20Crypto::decrypt(
                &key,
                &encrypted_result[4096 + MAC_LENGTH..8192 + 2 * MAC_LENGTH],
                &next_nonce,
                Some(&ad),
            )
            .unwrap(),
        );
        assert_eq!(bytes[4096..8192], recovered[4096..8192]);
        next_nonce = next_nonce.increment(1);
        recovered.extend_from_slice(
            &XChacha20Crypto::decrypt(
                &key,
                &encrypted_result[8192 + 2 * MAC_LENGTH..],
                &next_nonce,
                Some(&ad),
            )
            .unwrap(),
        );
        assert_eq!(bytes, recovered);
    }
}
