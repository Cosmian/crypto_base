use std::{
    cmp::min,
    convert::{TryFrom, TryInto},
    fmt::Display,
    ops::DerefMut,
    sync::Mutex,
    vec::Vec,
};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    AeadInPlace, Aes256Gcm,
}; // Or `Aes128Gcm`
use log::error;
use rand_core::{CryptoRng, RngCore};

use crate::{
    entropy::CsRng,
    symmetric_crypto::{Key as _, Nonce as _, SymmetricCrypto},
    Error,
};

// This implements AES 256 GCM, using a pure rust interface
// It will use the AES native interface on the CPU if available

pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const MAC_LENGTH: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub struct Key(pub [u8; KEY_LENGTH]);

impl super::Key for Key {
    const LENGTH: usize = KEY_LENGTH;

    /// Generate a new symmetric random `Key`
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = Key([0_u8; KEY_LENGTH]);
        rng.fill_bytes(&mut key.0);
        key
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Key {
    #[must_use]
    pub fn as_array(&self) -> [u8; 32] {
        self.0
    }
}

impl From<Key> for Vec<u8> {
    fn from(k: Key) -> Vec<u8> {
        k.0.to_vec()
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<'a> TryFrom<&'a [u8]> for Key {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let len = bytes.len();
        let b: [u8; KEY_LENGTH] = bytes.try_into().map_err(|_| {
            error!(
                "Invalid key of length: {}, expected length: {}",
                len, KEY_LENGTH
            );
            Error::KeyParseError
        })?;
        Ok(Self(b))
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nonce(pub [u8; NONCE_LENGTH]);

impl super::Nonce for Nonce {
    const LENGTH: usize = NONCE_LENGTH;

    fn new(rng: &mut CsRng) -> Self {
        let mut nonce = Nonce([0_u8; NONCE_LENGTH]);
        rng.fill_bytes(&mut nonce.0);
        nonce
    }

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
        let mut vec = self.0.to_vec();
        vec.extend_from_slice(&[0_u8; 128 - Self::LENGTH]);
        let mut v = u128::from_le_bytes(
            vec.try_into()
                .expect("This should never happen: nonce is 96 bit < 128 bits"),
        );
        v += increment as u128;
        Nonce(
            v.to_be_bytes()[0..Self::LENGTH]
                .try_into()
                .expect("This should never happen: nonce is 96 bit < 128 bits"),
        )
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

pub struct Aes256GcmCrypto {
    rng: Mutex<CsRng>,
}

impl Display for Aes256GcmCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Aes256GcmCrypto::description())
    }
}

impl PartialEq for Aes256GcmCrypto {
    // `rng` is a random generator so you obviously can't
    // compare with other `rng` instance
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

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
        Aes256GcmCrypto {
            rng: Mutex::new(CsRng::new()),
        }
    }

    fn description() -> String {
        format!(
            "AES 256 GCM pure Rust (key bits: {}, nonce bits: {}, tag bits: {})",
            KEY_LENGTH * 8,
            NONCE_LENGTH * 8,
            MAC_LENGTH * 8
        )
    }

    fn generate_random_bytes(&self, len: usize) -> Vec<u8> {
        self.rng
            .lock()
            .expect("a mutex lock failed")
            .generate_random_bytes(len)
    }

    fn generate_key_from_rnd(rnd_bytes: &[u8]) -> Result<Self::Key, Error> {
        Self::Key::try_from(rnd_bytes)
    }

    fn generate_key(&self) -> Self::Key {
        Key::new(
            self.rng
                .lock()
                .expect("Cannot get a hold on the mutex")
                .deref_mut(),
        )
    }

    fn generate_nonce(&self) -> Self::Nonce {
        Nonce::new(&mut self.rng.lock().expect("Cannot get a hold on the mutex"))
    }

    fn encrypt(
        &self,
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        encrypt_combined(key, bytes, nonce, additional_data)
    }

    fn decrypt(
        &self,
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        decrypt_combined(key, bytes, nonce, additional_data)
    }
}

/// Encrypts a message using a secret key and a public nonce in combined mode:
/// the encrypted message, as well as a tag authenticating both the confidential
/// message and non-confidential data, are put into the encrypted result.
///
/// The total length of the encrypted data is the message length + `MAC_LENGTH`
pub fn encrypt_combined(
    key: &Key,
    bytes: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let payload = if let Some(aad) = additional_data {
        Payload { msg: bytes, aad }
    } else {
        Payload::from(bytes)
    };
    cipher
        .encrypt(GenericArray::from_slice(&nonce.0), payload)
        .map_err(|e| anyhow::anyhow!(e))
}

/// Encrypts a message in place using a secret key and a public nonce in
/// detached mode: The a tag authenticating both the confidential
/// message and non-confidential data, are returned separately
///
/// The tag length is `MAC_LENGTH`
pub fn encrypt_in_place_detached(
    key: &Key,
    bytes: &mut [u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let additional_data = additional_data.unwrap_or_default();
    cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce.0), additional_data, bytes)
        .map_err(|e| anyhow::anyhow!(e))
        .map(|t| t.to_vec())
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
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let payload = if let Some(aad) = additional_data {
        Payload { msg: bytes, aad }
    } else {
        Payload::from(bytes)
    };
    cipher
        .decrypt(GenericArray::from_slice(&nonce.0), payload)
        .map_err(|e| anyhow::anyhow!(e))
}

/// Decrypts a message in pace in detached mode.
/// The bytes should not contain the authentication tag.
///
/// The provided additional data must match those provided during encryption for
/// the MAC to verify.
///
/// Decryption will never be performed, even partially, before verification.
pub fn decrypt_in_place_detached(
    key: &Key,
    bytes: &mut [u8],
    tag: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> anyhow::Result<()> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let additional_data = additional_data.unwrap_or_default();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&nonce.0),
            additional_data,
            bytes,
            GenericArray::from_slice(tag),
        )
        .map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::default();
        let key_1 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_1.0.len());
        let key_2 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_2.0.len());
        assert_ne!(key_1, key_2);
    }

    #[test]
    fn test_nonce() {
        let mut cs_rng = CsRng::default();
        let nonce_1 = Nonce::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_1.0.len());
        let nonce_2 = Nonce::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_2.0.len());
        assert_ne!(nonce_1, nonce_2);
    }

    #[test]
    fn test_random_bytes() {
        let mut cs_rng = CsRng::default();
        let size: usize = 1024;
        let random_bytes_1 = cs_rng.generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        let random_bytes_2 = cs_rng.generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        assert_ne!(random_bytes_1, random_bytes_2);
    }

    #[test]
    fn test_encryption_decryption_combined() -> anyhow::Result<()> {
        let mut cs_rng = CsRng::default();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes(8192);
        let iv = Nonce::new(&mut cs_rng);
        // no additional data
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, None)?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, encrypted_result.as_slice(), &iv, None)?;
        assert_eq!(bytes, recovered);
        // additional data
        let ad = cs_rng.generate_random_bytes(42);
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, Some(&ad))?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, encrypted_result.as_slice(), &iv, Some(&ad))?;
        assert_eq!(bytes, recovered);
        Ok(())
    }

    #[test]
    fn test_encryption_decryption_detached() -> anyhow::Result<()> {
        let mut cs_rng = CsRng::default();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes(8192);
        let iv = Nonce::new(&mut cs_rng);
        // no additional data
        let mut data = bytes.clone();
        let tag = encrypt_in_place_detached(&key, &mut data, &iv, None)?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(&key, &mut data, &tag, &iv, None)?;
        assert_eq!(bytes, data);
        // // additional data
        let ad = cs_rng.generate_random_bytes(42);
        let mut data = bytes.clone();
        let tag = encrypt_in_place_detached(&key, &mut data, &iv, Some(&ad))?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(&key, &mut data, &tag, &iv, Some(&ad))?;
        assert_eq!(bytes, data);
        Ok(())
    }
}
