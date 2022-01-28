// #![allow(clippy::cast_possible_truncation)]
use std::{
    cmp::min,
    convert::{TryFrom, TryInto},
    fmt::Display,
    vec::Vec,
};

use tracing::debug;

use super::{Key as GenericKey, Nonce as GenericNonce, SymmetricCrypto, MIN_DATA_LENGTH};
use crate::sodium_bindings::{
    crypto_aead_xchacha20poly1305_ietf_ABYTES, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt, randombytes_buf, sodium_increment, sodium_init,
};

pub const KEY_LENGTH: usize = crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;
pub const NONCE_LENGTH: usize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize;
pub const MAC_LENGTH: usize = crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;

#[derive(Clone, Debug, PartialEq)]
pub struct Key {
    b: [u8; KEY_LENGTH],
}

impl GenericKey for Key {
    const LENGTH: usize = KEY_LENGTH;

    fn try_from(bytes: Vec<u8>) -> anyhow::Result<Self> {
        bytes.try_into()
    }

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        bytes.try_into()
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.b.to_vec()
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let len = value.len();
        let b: [u8; KEY_LENGTH] = value.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid key of length: {}, expected length: {}",
                len,
                KEY_LENGTH
            )
        })?;
        Ok(Self { b })
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl From<Key> for Vec<u8> {
    fn from(k: Key) -> Vec<u8> {
        k.b.to_vec()
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.b))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nonce {
    b: [u8; NONCE_LENGTH],
}

impl GenericNonce for Nonce {
    const LENGTH: usize = NONCE_LENGTH;

    fn try_from(bytes: Vec<u8>) -> anyhow::Result<Self> {
        bytes.try_into()
    }

    fn try_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        bytes.try_into()
    }

    fn increment(&self, increment: usize) -> Self {
        let mut copy = self.clone();
        unsafe {
            let ptr = copy.b.as_mut_ptr();
            let len = copy.b.len() as u64;
            for _ in 0..increment {
                sodium_increment(ptr, len);
            }
        }
        copy
    }

    fn xor(&self, b2: &[u8]) -> Self {
        let mut n = self.b;
        for i in 0..min(b2.len(), NONCE_LENGTH) {
            n[i] ^= b2[i];
        }
        Nonce { b: n }
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.b.to_vec()
    }
}

impl TryFrom<&[u8]> for Nonce {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let len = value.len();

        let b: [u8; NONCE_LENGTH] = value.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid nonce of length: {}, expected length: {}",
                len,
                NONCE_LENGTH
            )
        })?;
        Ok(Self { b })
    }
}

impl TryFrom<Vec<u8>> for Nonce {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl From<Nonce> for Vec<u8> {
    fn from(n: Nonce) -> Vec<u8> {
        n.b.to_vec()
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.b))
    }
}

#[derive(Debug, PartialEq)]
pub struct XChacha20Crypto {}

impl Default for XChacha20Crypto {
    fn default() -> Self {
        Self::new()
    }
}

impl SymmetricCrypto for XChacha20Crypto {
    type Key = Key;
    type Nonce = Nonce;

    const MAC_LENGTH: usize = MAC_LENGTH;

    #[must_use]
    fn new() -> XChacha20Crypto {
        unsafe {
            sodium_init();
        };
        debug!("Instantiated XChaCha20");
        XChacha20Crypto {}
    }

    fn description() -> String {
        format!(
            "XChaCha20 Poly 1305 (key bits: {}, nonce bits: {}, mac bits: {})",
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

    fn generate_key_from_rnd(rnd_bytes: &[u8]) -> anyhow::Result<Self::Key> {
        Ok(Key {
            b: rnd_bytes.try_into()?,
        })
    }

    fn generate_key(&self) -> Self::Key {
        let mut bytes = [0_u8; KEY_LENGTH];
        unsafe {
            randombytes_buf(
                bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                bytes.len() as u64,
            );
        }
        Key { b: bytes }
    }

    fn generate_nonce(&self) -> Self::Nonce {
        let mut bytes = [0_u8; NONCE_LENGTH];
        unsafe {
            randombytes_buf(
                bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                bytes.len() as u64,
            );
        }
        Nonce { b: bytes }
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
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                result.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u64,
                ad,
                ad_len,
                nonce.b.as_ref().as_ptr(),
                key.b.as_ptr(),
            )
        } != 0
        {
            anyhow::bail!("decryption failed");
        }
        Ok(result)
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
            if crypto_aead_xchacha20poly1305_ietf_encrypt(
                result.as_mut_ptr(),
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u64,
                ad,
                ad_len,
                std::ptr::null(),
                nonce.b.as_ref().as_ptr(),
                key.b.as_ptr(),
            ) != 0
            {
                anyhow::bail!("encryption failed");
            };
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::{Nonce, SymmetricCrypto, XChacha20Crypto, KEY_LENGTH, MAC_LENGTH, NONCE_LENGTH};
    use crate::symmetric_crypto::Nonce as _;

    #[test]
    fn test_key() {
        let x_cha_cha = XChacha20Crypto::new();
        let key_1 = x_cha_cha.generate_key();
        assert_eq!(KEY_LENGTH, key_1.b.len());
        let key_2 = x_cha_cha.generate_key();
        assert_eq!(KEY_LENGTH, key_1.b.len());
        assert_ne!(key_1.b, key_2.b);
    }

    #[test]
    fn test_random_bytes() {
        let size = 1024_usize;
        let x_cha_cha = XChacha20Crypto::new();
        let random_bytes_1 = x_cha_cha.generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        let random_bytes_2 = x_cha_cha.generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        assert_ne!(random_bytes_1, random_bytes_2);
    }

    #[test]
    fn test_increment_nonce() {
        let mut nonce: Nonce = Nonce {
            b: [0_u8; NONCE_LENGTH],
        };
        let inc = 1_usize << 10;
        nonce = nonce.increment(inc);
        assert_eq!(
            "000400000000000000000000000000000000000000000000",
            hex::encode(nonce.b)
        );
    }

    #[test]
    fn test_encryption_decryption_xchacha20() {
        let crypto = XChacha20Crypto::new();
        let key = crypto.generate_key();
        let bytes = crypto.generate_random_bytes(8192);
        let ad = crypto.generate_random_bytes(56);
        let iv = crypto.generate_nonce();
        let encrypted_result = crypto.encrypt(&key, &bytes, &iv, Some(&ad)).unwrap();
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        // decrypt
        let recovered = crypto
            .decrypt(&key, encrypted_result.as_slice(), &iv, Some(&ad))
            .unwrap();
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn test_encryption_decryption_xchacha20_chunks() {
        let crypto = XChacha20Crypto::new();
        let key = crypto.generate_key();
        let bytes = crypto.generate_random_bytes(10000);
        let ad = crypto.generate_random_bytes(92);
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
