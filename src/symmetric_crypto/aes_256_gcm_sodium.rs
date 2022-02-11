// This implements AES 256 GCM, using lib sodium
// and requires an AES native interface on the CPU

use std::{cmp::min, convert::TryInto, fmt::Display, vec::Vec};

use tracing::debug;

use super::SymmetricCrypto;
use crate::{
    sodium_bindings::{
        crypto_aead_aes256gcm_ABYTES, crypto_aead_aes256gcm_KEYBYTES,
        crypto_aead_aes256gcm_NPUBBYTES, crypto_aead_aes256gcm_decrypt,
        crypto_aead_aes256gcm_decrypt_detached, crypto_aead_aes256gcm_encrypt,
        crypto_aead_aes256gcm_encrypt_detached, crypto_aead_aes256gcm_is_available,
        randombytes_buf, sodium_increment, sodium_init,
    },
    symmetric_crypto::{Key as _, MIN_DATA_LENGTH},
};

pub const KEY_LENGTH: usize = crypto_aead_aes256gcm_KEYBYTES as usize;
pub const NONCE_LENGTH: usize = crypto_aead_aes256gcm_NPUBBYTES as usize;
pub const MAC_LENGTH: usize = crypto_aead_aes256gcm_ABYTES as usize;

#[derive(Debug, Clone, PartialEq)]
pub struct Key(pub [u8; KEY_LENGTH]);

impl super::Key for Key {
    const LENGTH: usize = KEY_LENGTH;

    fn try_from(bytes: Vec<u8>) -> anyhow::Result<Self> {
        Self::try_from_slice(bytes.as_slice())
    }

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        let len = bytes.len();
        let b: [u8; KEY_LENGTH] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid key of length: {}, expected length: {}",
                len,
                KEY_LENGTH
            )
        })?;
        Ok(Self(b))
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<Key> for Vec<u8> {
    fn from(k: Key) -> Vec<u8> {
        k.0.to_vec()
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nonce(pub [u8; NONCE_LENGTH]);

impl Nonce {
    #[must_use]
    pub fn xor(&self, b2: &[u8]) -> Nonce {
        let mut n = self.0;
        for i in 0..min(b2.len(), NONCE_LENGTH) {
            n[i] ^= b2[i];
        }
        Nonce(n)
    }
}

impl super::Nonce for Nonce {
    const LENGTH: usize = NONCE_LENGTH;

    fn try_from(bytes: Vec<u8>) -> anyhow::Result<Self> {
        Self::try_from_slice(bytes.as_slice())
    }

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        let len = bytes.len();
        let b: [u8; NONCE_LENGTH] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid nonce of length: {}, expected length: {}",
                len,
                NONCE_LENGTH
            )
        })?;
        Ok(Self(b))
    }

    fn increment(&self, increment: usize) -> Self {
        increment_nonce(self, increment)
    }

    fn xor(&self, b2: &[u8]) -> Self {
        let mut n = self.0;
        for i in 0..min(b2.len(), NONCE_LENGTH) {
            n[i] ^= b2[i];
        }
        Nonce(n)
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<Nonce> for Vec<u8> {
    fn from(n: Nonce) -> Vec<u8> {
        n.0.to_vec()
    }
}

impl From<Key> for [u8; KEY_LENGTH] {
    fn from(k: Key) -> [u8; KEY_LENGTH] {
        k.0
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub fn init() -> anyhow::Result<()> {
    unsafe {
        sodium_init();
        anyhow::ensure!(
            crypto_aead_aes256gcm_is_available() == 1,
            "This CPU does not support the AES256-GCM implementation"
        );
    }
    Ok(())
}

/// Generate a 256 bit symmetric key appropriate for use with AES
#[must_use]
pub fn generate_key() -> Key {
    let mut bytes = [0_u8; KEY_LENGTH];
    unsafe {
        randombytes_buf(
            bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
            bytes.len() as u64,
        );
    }
    Key(bytes)
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
    Nonce(bytes)
}

/// Increment a nonce with the given value
///
/// a nonce  should never be re-used with the same key
#[must_use]
pub fn increment_nonce(nonce: &Nonce, add_value: usize) -> Nonce {
    let mut copy = nonce.clone();
    unsafe {
        let ptr = copy.0.as_mut_ptr();
        let len = copy.0.len() as u64;
        for _ in 0..add_value {
            sodium_increment(ptr, len);
        }
    }
    copy
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
) -> anyhow::Result<Vec<u8>> {
    let cipher_length = bytes.len() + MAC_LENGTH;
    let mut result: Vec<u8> = vec![0; cipher_length];
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
            nonce.0.as_ptr(),
            key.0.as_ptr(),
        );

        anyhow::ensure!(ret == 0, "encryption failed");
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
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let cipher_length = bytes.len();
    let mut result: Vec<u8> = vec![0; cipher_length];
    let mut mac: Vec<u8> = vec![0; MAC_LENGTH];
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
            nonce.0.as_ptr(),
            key.0.as_ptr(),
        );

        anyhow::ensure!(ret == 0, "encryption failed");

        anyhow::ensure!(
            mac_len == MAC_LENGTH as u64,
            "Invalid MAC length: {}. Expected: {}",
            mac_len,
            MAC_LENGTH
        );
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
) -> anyhow::Result<Vec<u8>> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    anyhow::ensure!(
        bytes.len() > MAC_LENGTH,
        "decryption failed - data too short"
    );
    let clear_text_length = bytes.len() - MAC_LENGTH;
    let mut result: Vec<u8> = vec![0; clear_text_length];
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
            nonce.0.as_ptr(),
            key.0.as_ptr(),
        );

        anyhow::ensure!(ret == 0, "decryption failed");
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
) -> anyhow::Result<Vec<u8>> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    anyhow::ensure!(
        bytes.len() > MAC_LENGTH,
        "decryption failed - data too short"
    );
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
            nonce.0.as_ptr(),
            key.0.as_ptr(),
        );

        anyhow::ensure!(ret == 0, "decryption failed");
    }
    Ok(result)
}

#[derive(Debug, PartialEq)]
pub struct Aes256GcmCrypto;

impl Default for Aes256GcmCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl SymmetricCrypto for Aes256GcmCrypto {
    type Key = Key;
    type Nonce = Nonce;

    const MAC_LENGTH: usize = MAC_LENGTH;

    #[must_use]
    fn new() -> Self {
        unsafe {
            sodium_init();
            if crypto_aead_aes256gcm_is_available() != 1 {
                panic!("This CPU does not support the AES256-GCM implementation");
            }
        };
        debug!("Instantiated AES 256 GCM");
        Aes256GcmCrypto {}
    }

    fn description() -> String {
        format!(
            "AES 256 GCM libsodium (key bits: {}, nonce bits: {}, mac bits: {})",
            KEY_LENGTH * 8,
            NONCE_LENGTH * 8,
            MAC_LENGTH * 8
        )
    }

    fn generate_random_bytes(&self, len: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0; len];
        unsafe {
            randombytes_buf(
                bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                bytes.len() as u64,
            );
        }
        bytes
    }

    fn generate_key_from_rnd(rng_bytes: &[u8]) -> anyhow::Result<Self::Key> {
        Self::Key::try_from_slice(rng_bytes)
    }

    fn generate_key(&self) -> Self::Key {
        let mut bytes = [0_u8; KEY_LENGTH];
        unsafe {
            randombytes_buf(
                bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                bytes.len() as u64,
            );
        }
        Key(bytes)
    }

    fn generate_nonce(&self) -> Self::Nonce {
        let mut bytes = [0_u8; NONCE_LENGTH];
        unsafe {
            randombytes_buf(
                bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                bytes.len() as u64,
            );
        }
        Nonce(bytes)
    }

    fn encrypt(
        &self,
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Nonce,
        additional_data: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        let (ad, ad_len) = match additional_data {
            Some(b) => (b.as_ptr(), b.len() as u64),
            None => (std::ptr::null(), 0_u64),
        };
        let cipher_length = bytes.len() + MAC_LENGTH;
        let mut result: Vec<u8> = vec![0; cipher_length];
        unsafe {
            if crypto_aead_aes256gcm_encrypt(
                result.as_mut_ptr(),
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u64,
                ad,
                ad_len,
                std::ptr::null(),
                nonce.0.as_ref().as_ptr(),
                key.0.as_ptr(),
            ) != 0
            {
                anyhow::bail!("encryption failed");
            };
        }
        Ok(result)
    }

    fn decrypt(
        &self,
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Nonce,
        additional_data: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        if bytes.is_empty() {
            return Ok(vec![]);
        }
        if bytes.len() < MAC_LENGTH + MIN_DATA_LENGTH {
            anyhow::bail!("decryption failed - data too short");
        }
        let clear_text_length = bytes.len() - MAC_LENGTH;
        let mut result: Vec<u8> = vec![0; clear_text_length];
        if unsafe {
            let (ad, ad_len) = match additional_data {
                Some(b) => (b.as_ptr(), b.len() as u64),
                None => (std::ptr::null(), 0_u64),
            };
            crypto_aead_aes256gcm_decrypt(
                result.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u64,
                ad,
                ad_len,
                nonce.0.as_ref().as_ptr(),
                key.0.as_ptr(),
            )
        } != 0
        {
            anyhow::bail!("decryption failed");
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::symmetric_crypto::Nonce as _;

    #[test]
    fn test_key() {
        let key_1 = generate_key();
        assert_eq!(KEY_LENGTH, key_1.0.len());
        let key_2 = generate_key();
        assert_eq!(KEY_LENGTH, key_2.0.len());
        assert_ne!(key_1, key_2);
    }

    #[test]
    fn test_nonce() {
        let nonce_1 = generate_nonce();
        assert_eq!(NONCE_LENGTH, nonce_1.0.len());
        let nonce_2 = generate_nonce();
        assert_eq!(NONCE_LENGTH, nonce_2.0.len());
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
        let mut nonce: Nonce = Nonce([0_u8; NONCE_LENGTH]);
        let inc = 1_usize << 10;
        nonce = increment_nonce(&nonce, inc);
        assert_eq!("000400000000000000000000", format!("{}", nonce));
    }

    #[test]
    fn test_encryption_decryption_combined() -> anyhow::Result<()> {
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
    fn test_encryption_decryption_detached() -> anyhow::Result<()> {
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
        let aes = Aes256GcmCrypto::new();
        let key = aes.generate_key();
        let bytes = aes.generate_random_bytes(8192);
        let ad = aes.generate_random_bytes(56);

        let iv = aes.generate_nonce();
        let encrypted_result = aes.encrypt(&key, &bytes, &iv, Some(&ad)).unwrap();
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        // decrypt
        let recovered = aes
            .decrypt(&key, encrypted_result.as_slice(), &iv, Some(&ad))
            .unwrap();
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn test_encryption_decryption_aes256gcm_chunks() {
        let crypto = Aes256GcmCrypto::new();
        let key = crypto.generate_key();
        let bytes = crypto.generate_random_bytes(10000);
        let ad = crypto.generate_random_bytes(56);

        let iv = crypto.generate_nonce();
        let mut encrypted_result: Vec<u8> = vec![];
        encrypted_result.extend_from_slice(
            &crypto
                .encrypt(&key, &bytes[..4096], &iv, Some(&ad))
                .unwrap(),
        );
        let mut next_nonce = iv.increment(1);
        encrypted_result.extend_from_slice(
            &crypto
                .encrypt(&key, &bytes[4096..8192], &next_nonce, Some(&ad))
                .unwrap(),
        );
        next_nonce = next_nonce.increment(1);
        encrypted_result.extend_from_slice(
            &crypto
                .encrypt(&key, &bytes[8192..], &next_nonce, Some(&ad))
                .unwrap(),
        );
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + 3 * MAC_LENGTH, encrypted_result.len());
        // decrypt
        let mut recovered: Vec<u8> = vec![];
        recovered.extend_from_slice(
            &crypto
                .decrypt(&key, &encrypted_result[..4096 + MAC_LENGTH], &iv, Some(&ad))
                .unwrap(),
        );
        let mut next_nonce = iv.increment(1);
        assert_eq!(bytes[..4096], recovered[..4096]);
        recovered.extend_from_slice(
            &crypto
                .decrypt(
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
            &crypto
                .decrypt(
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
