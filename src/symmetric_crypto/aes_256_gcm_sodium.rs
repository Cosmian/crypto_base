// This implements AES 256 GCM, using lib sodium
// and requires an AES native interface on the CPU

use crate::{
    sodium_bindings::{
        crypto_aead_aes256gcm_ABYTES, crypto_aead_aes256gcm_NPUBBYTES,
        crypto_aead_aes256gcm_decrypt, crypto_aead_aes256gcm_decrypt_detached,
        crypto_aead_aes256gcm_encrypt, crypto_aead_aes256gcm_encrypt_detached,
        crypto_aead_aes256gcm_is_available, randombytes_buf, sodium_increment, sodium_init,
    },
    symmetric_crypto::{SymmetricCrypto, MIN_DATA_LENGTH},
};
use aes::cipher::Unsigned;
use cosmian_crypto_core::{
    reexport::generic_array::{typenum::U32, GenericArray},
    symmetric_crypto::nonce::NonceTrait,
    CryptoCoreError,
};

/// AES256 uses 32-bytes keys
type KeyLength = U32;
pub const NONCE_LENGTH: usize = crypto_aead_aes256gcm_NPUBBYTES as usize;
pub const MAC_LENGTH: usize = crypto_aead_aes256gcm_ABYTES as usize;

pub type Key = cosmian_crypto_core::symmetric_crypto::key::Key<KeyLength>;
pub type Nonce = cosmian_crypto_core::symmetric_crypto::nonce::Nonce<NONCE_LENGTH>;

pub fn init() -> Result<(), CryptoCoreError> {
    unsafe {
        sodium_init();
        if crypto_aead_aes256gcm_is_available() != 1 {
            return Err(CryptoCoreError::HardwareCapability(
                "This CPU does not support the AES256-GCM implementation".to_string(),
            ));
        }
    }
    Ok(())
}

/// Generate a 256 bit symmetric key appropriate for use with AES
#[must_use]
pub fn generate_key() -> Key {
    let mut bytes = GenericArray::<u8, KeyLength>::default();
    unsafe {
        randombytes_buf(
            bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
            bytes.len() as u64,
        );
    }
    Key::from(bytes)
}

/// Generate a 96 bits nonce appropriate for use with AES
#[must_use]
pub fn generate_nonce() -> Nonce {
    let mut bytes = [0_u8; NONCE_LENGTH];
    unsafe {
        randombytes_buf(
            bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
            bytes.len() as u64,
        );
    }
    Nonce::from(bytes)
}

/// Increment a nonce with the given value
///
/// a nonce  should never be re-used with the same key
pub fn increment_nonce(nonce: &Nonce, add_value: usize) -> Result<Nonce, CryptoCoreError> {
    let mut nonce: Vec<u8> = nonce.as_slice().to_owned();
    unsafe {
        let ptr = nonce.as_mut_ptr();
        let len = nonce.len() as u64;
        for _ in 0..add_value {
            sodium_increment(ptr, len);
        }
    }
    Nonce::try_from(nonce)
}

/// Generate cryptographically secure (pseudo) random bytes of the given length
#[must_use]
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0; len];
    unsafe {
        randombytes_buf(
            bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
            bytes.len() as u64,
        );
    }
    bytes
}

/// Encrypts a message using a secret key and a public nonce in combined mode:
/// the encrypted message, as well as a tag authenticating both the confidential
/// message and non-confidential data, are put into the encrypted result.
///
/// The total length of the encrypted data is the message length + MAC_LENGTH
///
/// This function encrypts then tag: it can also be used as a MAC, with an empty
/// message.
pub fn encrypt_combined(
    key: &Key,
    bytes: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError> {
    let cipher_length = bytes.len() + MAC_LENGTH;
    let mut result = vec![0; cipher_length];
    unsafe {
        let (ad, ad_len) = match additional_data {
            Some(b) => (b.as_ptr(), b.len() as u64),
            None => (std::ptr::null(), 0_u64),
        };
        let ret = crypto_aead_aes256gcm_encrypt(
            result.as_mut_ptr(),
            std::ptr::null_mut(),
            bytes.as_ptr(),
            bytes.len() as u64,
            ad,
            ad_len,
            std::ptr::null(),
            nonce.as_slice().as_ptr(),
            key.as_slice().as_ptr(),
        );

        if ret != 0 {
            return Err(CryptoCoreError::EncryptionError(
                "Combined encryption failed".to_string(),
            ));
        }
    }
    Ok(result)
}

/// Encrypts a message using a secret key and a public nonce in detached mode:
/// the encrypted message, as well as a tag authenticating both the confidential
/// message and non-confidential data, are both returned.
///
/// The total length of the encrypted data is the message length,
/// and the authentication tag has length MAC_LENGTH
///
/// This function encrypts then tag: it can also be used as a MAC, with an empty
/// message.
pub fn encrypt_detached(
    key: &Key,
    bytes: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoCoreError> {
    let cipher_length = bytes.len();
    let mut result = vec![0; cipher_length];
    let mut mac = vec![0; MAC_LENGTH];
    let mut mac_len = 0_u64;
    unsafe {
        let (ad, ad_len) = match additional_data {
            Some(b) => (b.as_ptr(), b.len() as u64),
            None => (std::ptr::null(), 0_u64),
        };
        let ret = crypto_aead_aes256gcm_encrypt_detached(
            result.as_mut_ptr(),
            mac.as_mut_ptr(),
            &mut mac_len,
            bytes.as_ptr(),
            bytes.len() as u64,
            ad,
            ad_len,
            std::ptr::null(),
            nonce.as_slice().as_ptr(),
            key.as_slice().as_ptr(),
        );

        if ret != 0 {
            return Err(CryptoCoreError::EncryptionError(
                "Detached encryption failed".to_string(),
            ));
        }

        if mac_len != MAC_LENGTH as u64 {
            return Err(CryptoCoreError::InvalidSize(format!(
                "Invalid MAC length: {mac_len}. Expected: {MAC_LENGTH}"
            )));
        }
    }
    Ok((result, mac))
}

/// Decrypts a message in combined mode: the MAC is appended to the cipher text
///
/// The provided additional data must match those provided during encryption for
/// the MAC to verify.
///
/// Decryption will never be performed, even partially, before verification.
pub fn decrypt_combined(
    key: &Key,
    bytes: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    if bytes.len() <= MAC_LENGTH {
        return Err(CryptoCoreError::InvalidSize(
            "Not enough data for combined decryption".to_string(),
        ));
    }
    let clear_text_length = bytes.len() - MAC_LENGTH;
    let mut result = vec![0; clear_text_length];
    unsafe {
        let (ad, ad_len) = match additional_data {
            Some(b) => (b.as_ptr(), b.len() as u64),
            None => (std::ptr::null(), 0_u64),
        };
        let ret = crypto_aead_aes256gcm_decrypt(
            result.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            bytes.as_ptr(),
            bytes.len() as u64,
            ad,
            ad_len,
            nonce.as_slice().as_ptr(),
            key.as_slice().as_ptr(),
        );

        if ret != 0 {
            return Err(CryptoCoreError::DecryptionError(
                "Combined decryption failed".to_string(),
            ));
        }
    }
    Ok(result)
}

/// Decrypts a message in detached mode: the MAC is provided along the cipher
/// text
///
/// The provided additional data must match those provided during encryption for
/// the MAC to verify.
///
/// Decryption will never be performed, even partially, before verification.
pub fn decrypt_detached(
    key: &Key,
    bytes: &[u8],
    mac: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    if bytes.len() <= MAC_LENGTH {
        return Err(CryptoCoreError::InvalidSize(
            "Not enough data for detached decryption".to_string(),
        ));
    }
    let clear_text_length = bytes.len();
    let mut result: Vec<u8> = vec![0; clear_text_length];
    unsafe {
        let (ad, ad_len) = match additional_data {
            Some(b) => (b.as_ptr(), b.len() as u64),
            None => (std::ptr::null(), 0_u64),
        };
        let ret = crypto_aead_aes256gcm_decrypt_detached(
            result.as_mut_ptr(),
            std::ptr::null_mut(),
            bytes.as_ptr(),
            bytes.len() as u64,
            mac.as_ptr(),
            ad,
            ad_len,
            nonce.as_slice().as_ptr(),
            key.as_slice().as_ptr(),
        );

        if ret != 0 {
            return Err(CryptoCoreError::DecryptionError(
                "Detached decryption failed".to_string(),
            ));
        }
    }
    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Aes256GcmCrypto;

impl SymmetricCrypto for Aes256GcmCrypto {
    type Key = Key;
    type Nonce = Nonce;

    const MAC_LENGTH: usize = MAC_LENGTH;

    fn description() -> String {
        format!(
            "AES 256 GCM libsodium (key bits: {}, nonce bits: {}, mac bits: {})",
            KeyLength::to_usize() * 8,
            NONCE_LENGTH * 8,
            MAC_LENGTH * 8
        )
    }

    fn encrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        let (ad, ad_len) = match additional_data {
            Some(b) => (b.as_ptr(), b.len() as u64),
            None => (std::ptr::null(), 0_u64),
        };
        let cipher_length = bytes.len() + MAC_LENGTH;
        let mut result = vec![0; cipher_length];
        unsafe {
            let ret = crypto_aead_aes256gcm_encrypt(
                result.as_mut_ptr(),
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u64,
                ad,
                ad_len,
                std::ptr::null(),
                nonce.as_slice().as_ptr(),
                key.as_slice().as_ptr(),
            );
            if ret != 0 {
                return Err(CryptoCoreError::EncryptionError(
                    "AEAD AES256 GCM encryption failed".to_string(),
                ));
            };
        }
        Ok(result)
    }

    fn decrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        if bytes.is_empty() {
            return Ok(vec![]);
        }
        if bytes.len() < MAC_LENGTH + MIN_DATA_LENGTH {
            return Err(CryptoCoreError::DecryptionError(
                "Not enough data for AEAD AES256 GCM decryption".to_string(),
            ));
        }
        let clear_text_length = bytes.len() - MAC_LENGTH;
        let mut result = vec![0; clear_text_length];
        unsafe {
            let (ad, ad_len) = match additional_data {
                Some(b) => (b.as_ptr(), b.len() as u64),
                None => (std::ptr::null(), 0_u64),
            };
            let ret = crypto_aead_aes256gcm_decrypt(
                result.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u64,
                ad,
                ad_len,
                nonce.as_slice().as_ptr(),
                key.as_slice().as_ptr(),
            );
            if ret != 0 {
                return Err(CryptoCoreError::DecryptionError(
                    "AEAD AES256 GCM decryption failed".to_string(),
                ));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {

    use cosmian_crypto_core::reexport::generic_array::typenum::{Unsigned, U10000, U56, U8192};

    use crate::{
        entropy::CsRng,
        symmetric_crypto::{
            aes_256_gcm_sodium::{
                decrypt_combined, decrypt_detached, encrypt_combined, encrypt_detached,
                generate_key, generate_nonce, generate_random_bytes, increment_nonce,
                Aes256GcmCrypto, Key, KeyLength, Nonce, MAC_LENGTH, NONCE_LENGTH,
            },
            nonce::NonceTrait,
            SymmetricCrypto,
        },
        CryptoBaseError,
    };

    #[test]
    fn test_key() {
        let key_1 = generate_key();
        assert_eq!(KeyLength::to_usize(), key_1.as_slice().len());
        let key_2 = generate_key();
        assert_eq!(KeyLength::to_usize(), key_2.as_slice().len());
        assert_ne!(key_1, key_2);
    }

    #[test]
    fn test_nonce() {
        let nonce_1 = generate_nonce();
        assert_eq!(NONCE_LENGTH, nonce_1.as_slice().len());
        let nonce_2 = generate_nonce();
        assert_eq!(NONCE_LENGTH, nonce_2.as_slice().len());
        assert_ne!(nonce_1, nonce_2);
    }

    #[test]
    fn test_random_bytes() {
        let size = 1024_usize;
        let random_bytes_1 = generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        let random_bytes_2 = generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        assert_ne!(random_bytes_1, random_bytes_2);
    }

    #[test]
    fn test_increment_nonce() {
        let mut nonce: Nonce = Nonce::from([0_u8; NONCE_LENGTH]);
        let inc = 1_usize << 10;
        nonce = increment_nonce(&nonce, inc).unwrap();
        assert_eq!("000400000000000000000000", format!("{}", nonce));
    }

    #[test]
    fn test_encryption_decryption_combined() -> Result<(), CryptoBaseError> {
        let key = generate_key();
        let bytes = generate_random_bytes(8192);
        let iv = generate_nonce();
        // no additional data
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, None)?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, encrypted_result.as_slice(), &iv, None)?;
        assert_eq!(bytes, recovered);
        // additional data
        let ad = generate_random_bytes(42);
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, Some(&ad))?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, encrypted_result.as_slice(), &iv, Some(&ad))?;
        assert_eq!(bytes, recovered);
        Ok(())
    }

    #[ignore]
    #[test]
    fn test_encryption_decryption_detached() -> Result<(), CryptoBaseError> {
        let key = generate_key();
        let bytes = generate_random_bytes(8192);
        let iv = generate_nonce();
        // no additional data
        let (encrypted_result, mac) = encrypt_detached(&key, &bytes, &iv, None)?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len(), encrypted_result.len());
        assert_eq!(MAC_LENGTH, mac.len());
        let recovered =
            decrypt_detached(&key, encrypted_result.as_slice(), mac.as_slice(), &iv, None)?;
        assert_eq!(bytes, recovered);
        // additional data
        let ad = generate_random_bytes(42);
        let (encrypted_result, mac) = encrypt_detached(&key, &bytes, &iv, Some(&ad))?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len(), encrypted_result.len());
        assert_eq!(MAC_LENGTH, mac.len());
        let recovered = decrypt_detached(
            &key,
            encrypted_result.as_slice(),
            mac.as_slice(),
            &iv,
            Some(&ad),
        )?;
        assert_eq!(bytes, recovered);
        Ok(())
    }

    #[test]
    fn test_encryption_decryption_aes256gcm() {
        let mut cs_rng = CsRng::new();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes::<U8192>();
        let ad = cs_rng.generate_random_bytes::<U56>();
        let iv = Nonce::new(&mut cs_rng);

        let encrypted_result = Aes256GcmCrypto::encrypt(&key, &bytes, &iv, Some(&ad)).unwrap();
        assert_ne!(encrypted_result, bytes.to_vec());
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        // decrypt
        let recovered =
            Aes256GcmCrypto::decrypt(&key, encrypted_result.as_slice(), &iv, Some(&ad)).unwrap();
        assert_eq!(bytes.to_vec(), recovered);
    }

    #[test]
    fn test_encryption_decryption_aes256gcm_chunks() {
        let mut cs_rng = CsRng::new();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes::<U10000>();
        let ad = cs_rng.generate_random_bytes::<U56>();
        let iv = Nonce::new(&mut cs_rng);

        let mut encrypted_result: Vec<u8> = vec![];
        encrypted_result.extend_from_slice(
            &Aes256GcmCrypto::encrypt(&key, &bytes[..4096], &iv, Some(&ad)).unwrap(),
        );
        let mut next_nonce = iv.increment(1);
        encrypted_result.extend_from_slice(
            &Aes256GcmCrypto::encrypt(&key, &bytes[4096..8192], &next_nonce, Some(&ad)).unwrap(),
        );
        next_nonce = next_nonce.increment(1);
        encrypted_result.extend_from_slice(
            &Aes256GcmCrypto::encrypt(&key, &bytes[8192..], &next_nonce, Some(&ad)).unwrap(),
        );
        assert_ne!(encrypted_result, bytes.to_vec());
        assert_eq!(bytes.len() + 3 * MAC_LENGTH, encrypted_result.len());
        // decrypt
        let mut recovered: Vec<u8> = vec![];
        recovered.extend_from_slice(
            &Aes256GcmCrypto::decrypt(&key, &encrypted_result[..4096 + MAC_LENGTH], &iv, Some(&ad))
                .unwrap(),
        );
        let mut next_nonce = iv.increment(1);
        assert_eq!(bytes[..4096], recovered[..4096]);
        recovered.extend_from_slice(
            &Aes256GcmCrypto::decrypt(
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
            &Aes256GcmCrypto::decrypt(
                &key,
                &encrypted_result[8192 + 2 * MAC_LENGTH..],
                &next_nonce,
                Some(&ad),
            )
            .unwrap(),
        );
        assert_eq!(bytes.to_vec(), recovered);
    }
}
